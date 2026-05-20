use forensicnomicon::evtx::{
    DefenderEvent, LateralMovementEvent, ProcessExecution, RdpSessionEvent, ScheduledTask,
    SmbAccessEvent, WmiEvent,
};

// ── LateralMovementEvent ──────────────────────────────────────────────────────

#[test]
fn lateral_movement_event_has_expected_fields() {
    let e = LateralMovementEvent {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 4648,
        source_user: Some("DOMAIN\\alice".to_owned()),
        target_user: Some("DOMAIN\\bob".to_owned()),
        target_host: Some("DC01".to_owned()),
        logon_type: Some(3),
        auth_package: None,
        encryption_type: None,
    };
    assert_eq!(e.event_id, 4648);
    assert!(format!("{e:?}").contains("LateralMovementEvent"));
}

// ── RdpSessionEvent ───────────────────────────────────────────────────────────

#[test]
fn rdp_session_event_has_expected_fields() {
    let e = RdpSessionEvent {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 4778,
        user: Some("alice".to_owned()),
        session_id: Some(1),
        source_ip: Some("192.168.1.5".to_owned()),
    };
    assert_eq!(e.event_id, 4778);
    assert!(format!("{e:?}").contains("RdpSessionEvent"));
}

// ── SmbAccessEvent ────────────────────────────────────────────────────────────

#[test]
fn smb_access_event_has_expected_fields() {
    let e = SmbAccessEvent {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 5140,
        subject_user: Some("DOMAIN\\alice".to_owned()),
        share_name: Some("\\\\*\\IPC$".to_owned()),
        share_path: None,
        relative_target: None,
        ip_address: Some("10.0.0.1".to_owned()),
    };
    assert_eq!(e.event_id, 5140);
    assert!(format!("{e:?}").contains("SmbAccessEvent"));
}

// ── DefenderEvent ─────────────────────────────────────────────────────────────

#[test]
fn defender_event_has_expected_fields() {
    let e = DefenderEvent {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 1116,
        threat_name: Some("Trojan:Win32/Meterpreter".to_owned()),
        severity: Some("High".to_owned()),
        path: Some("C:\\Users\\alice\\Downloads\\evil.exe".to_owned()),
        action_taken: Some("Quarantine".to_owned()),
        process_name: None,
    };
    assert_eq!(e.event_id, 1116);
    assert!(format!("{e:?}").contains("DefenderEvent"));
}

// ── WmiEvent ──────────────────────────────────────────────────────────────────

#[test]
fn wmi_event_has_expected_fields() {
    let e = WmiEvent {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 5861,
        provider: Some("Microsoft-Windows-WMI-Activity".to_owned()),
        filter_name: Some("BotFilter82".to_owned()),
        consumer_name: Some("BotConsumer23".to_owned()),
        query: Some("SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'".to_owned()),
    };
    assert_eq!(e.event_id, 5861);
    assert!(format!("{e:?}").contains("WmiEvent"));
}

// ── ScheduledTask ─────────────────────────────────────────────────────────────

#[test]
fn scheduled_task_has_expected_fields() {
    let e = ScheduledTask {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 4698,
        task_name: Some("\\Microsoft\\Windows\\Evil\\Backdoor".to_owned()),
        task_content: Some("<Task><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>".to_owned()),
        subject_user: Some("DOMAIN\\alice".to_owned()),
    };
    assert_eq!(e.event_id, 4698);
    assert!(format!("{e:?}").contains("ScheduledTask"));
}

// ── ProcessExecution ──────────────────────────────────────────────────────────

#[test]
fn process_execution_has_expected_fields() {
    let e = ProcessExecution {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        pid: 1234,
        parent_pid: 5678,
        image: "C:\\Windows\\System32\\cmd.exe".to_owned(),
        command_line: "cmd.exe /c whoami".to_owned(),
        parent_image: Some("C:\\Windows\\explorer.exe".to_owned()),
        is_lolbin: false,
    };
    assert_eq!(e.pid, 1234);
    assert!(format!("{e:?}").contains("ProcessExecution"));
}
