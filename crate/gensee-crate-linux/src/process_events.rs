#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]

use std::io;

const NETLINK_HEADER_LEN: usize = 16;
const CONNECTOR_HEADER_LEN: usize = 20;
const PROCESS_EVENT_HEADER_LEN: usize = 16;
const CONNECTOR_INDEX_PROCESS: u32 = 1;
const CONNECTOR_VALUE_PROCESS: u32 = 1;
const PROCESS_EVENT_NONE: u32 = 0;
const PROCESS_EVENT_FORK: u32 = 0x0000_0001;
const PROCESS_EVENT_EXEC: u32 = 0x0000_0002;
const PROCESS_EVENT_EXIT: u32 = 0x8000_0000;
const NETLINK_MESSAGE_OVERRUN: u16 = 4;
#[cfg(target_os = "linux")]
const MAX_DATAGRAMS_PER_DRAIN: usize = 1_024;

/// A loss-detecting process lifecycle event emitted by the Linux process
/// connector. PIDs are from the initial PID namespace, matching Podman's
/// inspected container PID and the host cgroup.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LinuxProcessEvent {
    Fork {
        parent_pid: u32,
        parent_tgid: u32,
        child_pid: u32,
        child_tgid: u32,
        timestamp_ns: u64,
    },
    Exec {
        process_pid: u32,
        process_tgid: u32,
        timestamp_ns: u64,
    },
    Exit {
        process_pid: u32,
        process_tgid: u32,
        exit_code: u32,
        exit_signal: u32,
        parent_pid: u32,
        parent_tgid: u32,
        timestamp_ns: u64,
    },
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ConnectorMessage {
    sequence: u32,
    acknowledgement: u32,
    acknowledgement_error: Option<u32>,
    event: Option<LinuxProcessEvent>,
}

/// Host-owned process lifecycle sensor. Construction waits for the kernel's
/// subscription acknowledgement; receive-buffer overflow and malformed
/// connector messages are surfaced as errors so callers cannot claim complete
/// telemetry after loss.
pub struct LinuxProcessEventSensor {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
    #[cfg(target_os = "linux")]
    port_id: u32,
}

impl LinuxProcessEventSensor {
    pub fn new() -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "process lifecycle telemetry requires the Linux process connector",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            platform::open_sensor()
        }
    }

    pub fn handle_events_once(&mut self) -> io::Result<Vec<LinuxProcessEvent>> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "process lifecycle telemetry requires the Linux process connector",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            platform::drain_events(self.fd)
        }
    }
}

fn parse_connector_datagram(data: &[u8]) -> io::Result<Vec<ConnectorMessage>> {
    let mut messages = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if data.len() - offset < NETLINK_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated process-connector netlink header",
            ));
        }
        let message_len = read_u32(data, offset)? as usize;
        let message_type = read_u16(data, offset + 4)?;
        if message_len < NETLINK_HEADER_LEN || message_len > data.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid process-connector netlink message length",
            ));
        }
        if message_type == NETLINK_MESSAGE_OVERRUN {
            return Err(io::Error::other(
                "process-connector reported event loss; process coverage is incomplete",
            ));
        }
        if message_len >= NETLINK_HEADER_LEN + CONNECTOR_HEADER_LEN {
            let connector = offset + NETLINK_HEADER_LEN;
            let index = read_u32(data, connector)?;
            let value = read_u32(data, connector + 4)?;
            if index == CONNECTOR_INDEX_PROCESS && value == CONNECTOR_VALUE_PROCESS {
                let sequence = read_u32(data, connector + 8)?;
                let acknowledgement = read_u32(data, connector + 12)?;
                let payload_len = read_u16(data, connector + 16)? as usize;
                let payload = connector + CONNECTOR_HEADER_LEN;
                let connector_end = offset + message_len;
                if payload_len > connector_end.saturating_sub(payload) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated process-connector payload",
                    ));
                }
                let payload = &data[payload..payload + payload_len];
                messages.push(parse_process_message(sequence, acknowledgement, payload)?);
            }
        }
        let aligned = align_netlink(message_len);
        if aligned > data.len() - offset {
            if message_len == data.len() - offset {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated process-connector alignment padding",
            ));
        }
        offset += aligned;
    }
    Ok(messages)
}

fn parse_process_message(
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> io::Result<ConnectorMessage> {
    if payload.len() < PROCESS_EVENT_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated process event header",
        ));
    }
    let what = read_u32(payload, 0)?;
    let timestamp_ns = read_u64(payload, 8)?;
    let body = &payload[PROCESS_EVENT_HEADER_LEN..];
    let (acknowledgement_error, event) = match what {
        PROCESS_EVENT_NONE => (Some(read_u32(body, 0)?), None),
        PROCESS_EVENT_FORK => (
            None,
            Some(LinuxProcessEvent::Fork {
                parent_pid: read_u32(body, 0)?,
                parent_tgid: read_u32(body, 4)?,
                child_pid: read_u32(body, 8)?,
                child_tgid: read_u32(body, 12)?,
                timestamp_ns,
            }),
        ),
        PROCESS_EVENT_EXEC => (
            None,
            Some(LinuxProcessEvent::Exec {
                process_pid: read_u32(body, 0)?,
                process_tgid: read_u32(body, 4)?,
                timestamp_ns,
            }),
        ),
        PROCESS_EVENT_EXIT => (
            None,
            Some(LinuxProcessEvent::Exit {
                process_pid: read_u32(body, 0)?,
                process_tgid: read_u32(body, 4)?,
                exit_code: read_u32(body, 8)?,
                exit_signal: read_u32(body, 12)?,
                parent_pid: read_u32(body, 16)?,
                parent_tgid: read_u32(body, 20)?,
                timestamp_ns,
            }),
        ),
        _ => (None, None),
    };
    Ok(ConnectorMessage {
        sequence,
        acknowledgement,
        acknowledgement_error,
        event,
    })
}

fn read_u16(data: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = data.get(offset..offset + 2).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated process event field")
    })?;
    Ok(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> io::Result<u32> {
    let bytes = data.get(offset..offset + 4).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated process event field")
    })?;
    Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> io::Result<u64> {
    let bytes = data.get(offset..offset + 8).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "truncated process event field")
    })?;
    Ok(u64::from_ne_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn align_netlink(value: usize) -> usize {
    value.saturating_add(3) & !3
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::mem;
    use std::os::fd::RawFd;
    use std::time::{Duration, Instant};

    const NETLINK_CONNECTOR: libc::c_int = 11;
    const NETLINK_MESSAGE_DONE: u16 = 3;
    const PROCESS_MULTICAST_LISTEN: u32 = 1;
    const PROCESS_MULTICAST_IGNORE: u32 = 2;
    const SUBSCRIPTION_SEQUENCE: u32 = 1;
    const RECEIVE_BUFFER_BYTES: libc::c_int = 4 * 1024 * 1024;
    const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(1);

    pub(super) fn open_sensor() -> io::Result<LinuxProcessEventSensor> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                NETLINK_CONNECTOR,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let set_buffer = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &RECEIVE_BUFFER_BYTES as *const _ as *const libc::c_void,
                    mem::size_of_val(&RECEIVE_BUFFER_BYTES) as libc::socklen_t,
                )
            };
            if set_buffer < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut local: libc::sockaddr_nl = unsafe { mem::zeroed() };
            local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            local.nl_groups = CONNECTOR_INDEX_PROCESS;
            let bound = unsafe {
                libc::bind(
                    fd,
                    &local as *const _ as *const libc::sockaddr,
                    mem::size_of_val(&local) as libc::socklen_t,
                )
            };
            if bound < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut length = mem::size_of_val(&local) as libc::socklen_t;
            let named = unsafe {
                libc::getsockname(fd, &mut local as *mut _ as *mut libc::sockaddr, &mut length)
            };
            if named < 0 || local.nl_pid == 0 {
                return Err(if named < 0 {
                    io::Error::last_os_error()
                } else {
                    io::Error::other("kernel did not assign a process-connector port id")
                });
            }
            send_subscription(
                fd,
                local.nl_pid,
                PROCESS_MULTICAST_LISTEN,
                SUBSCRIPTION_SEQUENCE,
            )?;
            wait_for_subscription_ack(fd, SUBSCRIPTION_SEQUENCE)?;
            Ok(LinuxProcessEventSensor {
                fd,
                port_id: local.nl_pid,
            })
        })();
        if result.is_err() {
            unsafe { libc::close(fd) };
        }
        result
    }

    pub(super) fn drain_events(fd: RawFd) -> io::Result<Vec<LinuxProcessEvent>> {
        let mut events = Vec::new();
        for _ in 0..MAX_DATAGRAMS_PER_DRAIN {
            let Some(data) = receive_datagram(fd)? else {
                return Ok(events);
            };
            for message in parse_connector_datagram(&data)? {
                if let Some(error) = message.acknowledgement_error {
                    if error != 0 {
                        return Err(io::Error::other(format!(
                            "process-connector acknowledgement failed with kernel error {error}"
                        )));
                    }
                }
                if let Some(event) = message.event {
                    events.push(event);
                }
            }
        }
        Err(io::Error::other(
            "process-connector drain exceeded its bound; process coverage is incomplete",
        ))
    }

    fn wait_for_subscription_ack(fd: RawFd, expected_sequence: u32) -> io::Result<()> {
        let deadline = Instant::now() + SUBSCRIPTION_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for process-connector subscription acknowledgement",
                ));
            }
            let timeout_ms = remaining.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
            let mut poll_fd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if polled == 0 {
                continue;
            }
            let Some(data) = receive_datagram(fd)? else {
                continue;
            };
            for message in parse_connector_datagram(&data)? {
                if message.sequence == expected_sequence && message.acknowledgement == 1 {
                    let error = message.acknowledgement_error.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "process-connector acknowledgement had no status",
                        )
                    })?;
                    if error == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::other(format!(
                        "process-connector subscription failed with kernel error {error}"
                    )));
                }
            }
        }
    }

    fn receive_datagram(fd: RawFd) -> io::Result<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; 64 * 1024];
        let received = loop {
            let received = unsafe {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if received >= 0 {
                break received;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error);
        };
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "process-connector socket closed",
            ));
        }
        buffer.truncate(received as usize);
        Ok(Some(buffer))
    }

    fn send_subscription(fd: RawFd, port_id: u32, operation: u32, sequence: u32) -> io::Result<()> {
        // The four-byte multicast operation is the stable legacy ABI. Current
        // kernels accept it and default to all process events; using it keeps
        // the sensor compatible with kernels that predate the optional
        // eight-byte event filter. Non-lifecycle events are ignored below.
        let payload_len = 4usize;
        let message_len = NETLINK_HEADER_LEN + CONNECTOR_HEADER_LEN + payload_len;
        let mut message = vec![0u8; message_len];
        put_u32(&mut message, 0, message_len as u32);
        put_u16(&mut message, 4, NETLINK_MESSAGE_DONE);
        put_u32(&mut message, 8, sequence);
        put_u32(&mut message, 12, port_id);
        put_u32(&mut message, NETLINK_HEADER_LEN, CONNECTOR_INDEX_PROCESS);
        put_u32(
            &mut message,
            NETLINK_HEADER_LEN + 4,
            CONNECTOR_VALUE_PROCESS,
        );
        put_u32(&mut message, NETLINK_HEADER_LEN + 8, sequence);
        put_u16(&mut message, NETLINK_HEADER_LEN + 16, payload_len as u16);
        put_u32(
            &mut message,
            NETLINK_HEADER_LEN + CONNECTOR_HEADER_LEN,
            operation,
        );
        let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                fd,
                message.as_ptr() as *const libc::c_void,
                message.len(),
                0,
                &kernel as *const _ as *const libc::sockaddr,
                mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != message.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short process-connector subscription write",
            ));
        }
        Ok(())
    }

    fn put_u16(target: &mut [u8], offset: usize, value: u16) {
        target[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
    }

    fn put_u32(target: &mut [u8], offset: usize, value: u32) {
        target[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    impl Drop for LinuxProcessEventSensor {
        fn drop(&mut self) {
            let _ = send_subscription(
                self.fd,
                self.port_id,
                PROCESS_MULTICAST_IGNORE,
                SUBSCRIPTION_SEQUENCE + 1,
            );
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(what: u32, body: &[u32]) -> Vec<u8> {
        let process_len = 40usize;
        let message_len = NETLINK_HEADER_LEN + CONNECTOR_HEADER_LEN + process_len;
        let mut message = vec![0u8; align_netlink(message_len)];
        message[0..4].copy_from_slice(&(message_len as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&3u16.to_ne_bytes());
        message[NETLINK_HEADER_LEN..NETLINK_HEADER_LEN + 4]
            .copy_from_slice(&CONNECTOR_INDEX_PROCESS.to_ne_bytes());
        message[NETLINK_HEADER_LEN + 4..NETLINK_HEADER_LEN + 8]
            .copy_from_slice(&CONNECTOR_VALUE_PROCESS.to_ne_bytes());
        message[NETLINK_HEADER_LEN + 8..NETLINK_HEADER_LEN + 12]
            .copy_from_slice(&7u32.to_ne_bytes());
        message[NETLINK_HEADER_LEN + 12..NETLINK_HEADER_LEN + 16]
            .copy_from_slice(&9u32.to_ne_bytes());
        message[NETLINK_HEADER_LEN + 16..NETLINK_HEADER_LEN + 18]
            .copy_from_slice(&(process_len as u16).to_ne_bytes());
        let process = NETLINK_HEADER_LEN + CONNECTOR_HEADER_LEN;
        message[process..process + 4].copy_from_slice(&what.to_ne_bytes());
        message[process + 8..process + 16].copy_from_slice(&1234u64.to_ne_bytes());
        for (index, value) in body.iter().enumerate() {
            let offset = process + PROCESS_EVENT_HEADER_LEN + index * 4;
            message[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        message
    }

    #[test]
    fn parses_fork_exec_and_exit_messages() {
        let mut datagram = message(PROCESS_EVENT_FORK, &[10, 10, 11, 11]);
        datagram.extend(message(PROCESS_EVENT_EXEC, &[11, 11]));
        datagram.extend(message(PROCESS_EVENT_EXIT, &[11, 11, 3 << 8, 0, 10, 10]));
        let parsed = parse_connector_datagram(&datagram).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0].event,
            Some(LinuxProcessEvent::Fork {
                parent_pid: 10,
                parent_tgid: 10,
                child_pid: 11,
                child_tgid: 11,
                timestamp_ns: 1234,
            })
        );
        assert!(matches!(
            parsed[1].event,
            Some(LinuxProcessEvent::Exec {
                process_pid: 11,
                ..
            })
        ));
        assert!(matches!(
            parsed[2].event,
            Some(LinuxProcessEvent::Exit { exit_code: 768, .. })
        ));
    }

    #[test]
    fn rejects_truncated_connector_payload() {
        let mut data = message(PROCESS_EVENT_EXEC, &[11, 11]);
        data[NETLINK_HEADER_LEN + 16..NETLINK_HEADER_LEN + 18]
            .copy_from_slice(&u16::MAX.to_ne_bytes());
        assert_eq!(
            parse_connector_datagram(&data).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn parses_subscription_acknowledgement_identity_and_status() {
        let parsed = parse_connector_datagram(&message(PROCESS_EVENT_NONE, &[0])).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].sequence, 7);
        assert_eq!(parsed[0].acknowledgement, 9);
        assert_eq!(parsed[0].acknowledgement_error, Some(0));
        assert_eq!(parsed[0].event, None);
    }

    #[test]
    fn rejects_netlink_overrun() {
        let mut data = vec![0u8; NETLINK_HEADER_LEN];
        data[0..4].copy_from_slice(&(NETLINK_HEADER_LEN as u32).to_ne_bytes());
        data[4..6].copy_from_slice(&NETLINK_MESSAGE_OVERRUN.to_ne_bytes());
        assert!(parse_connector_datagram(&data)
            .unwrap_err()
            .to_string()
            .contains("event loss"));
    }
}
