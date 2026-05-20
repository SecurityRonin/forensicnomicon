use forensicnomicon::evtx::{
    DefenderEvent, EvtxEvent, LateralMovementEvent, ProcessExecution, RdpSessionEvent,
    ScheduledTask, SmbAccessEvent, WmiEvent,
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
        event_id: 4688,
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

// ── EvtxEvent tagged enum ─────────────────────────────────────────────────────

#[test]
fn evtx_event_lateral_movement_variant_wraps_inner() {
    let inner = LateralMovementEvent {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 4648,
        source_user: None,
        target_user: None,
        target_host: None,
        logon_type: None,
        auth_package: None,
        encryption_type: None,
    };
    let ev = EvtxEvent::LateralMovement(inner);
    assert!(format!("{ev:?}").contains("LateralMovement"));
}

#[test]
fn evtx_event_defender_variant_wraps_inner() {
    let inner = DefenderEvent {
        timestamp: "2024-01-01T00:00:00Z".to_owned(),
        event_id: 1116,
        threat_name: Some("Trojan".to_owned()),
        severity: None,
        path: None,
        action_taken: None,
        process_name: None,
    };
    let ev = EvtxEvent::Defender(inner);
    assert!(format!("{ev:?}").contains("Defender"));
}

#[test]
fn evtx_event_all_variants_are_present() {
    // Exhaustive match — compile error if a variant is missing.
    let samples: Vec<EvtxEvent> = vec![
        EvtxEvent::LateralMovement(LateralMovementEvent {
            timestamp: String::new(), event_id: 4648,
            source_user: None, target_user: None, target_host: None,
            logon_type: None, auth_package: None, encryption_type: None,
        }),
        EvtxEvent::RdpSession(RdpSessionEvent {
            timestamp: String::new(), event_id: 4778,
            user: None, session_id: None, source_ip: None,
        }),
        EvtxEvent::SmbAccess(SmbAccessEvent {
            timestamp: String::new(), event_id: 5140,
            subject_user: None, share_name: None, share_path: None,
            relative_target: None, ip_address: None,
        }),
        EvtxEvent::Defender(DefenderEvent {
            timestamp: String::new(), event_id: 1116,
            threat_name: None, severity: None, path: None,
            action_taken: None, process_name: None,
        }),
        EvtxEvent::Wmi(WmiEvent {
            timestamp: String::new(), event_id: 5861,
            provider: None, filter_name: None, consumer_name: None, query: None,
        }),
        EvtxEvent::ScheduledTask(ScheduledTask {
            timestamp: String::new(), event_id: 4698,
            task_name: None, task_content: None, subject_user: None,
        }),
        EvtxEvent::ProcessExecution(ProcessExecution {
            timestamp: String::new(), event_id: 4688,
            pid: 0, parent_pid: 0,
            image: String::new(), command_line: String::new(),
            parent_image: None, is_lolbin: false,
        }),
    ];
    assert_eq!(samples.len(), 7);
}

#[test]
fn evtx_event_timestamp_accessor_returns_inner_timestamp() {
    let ev = EvtxEvent::LateralMovement(LateralMovementEvent {
        timestamp: "2024-06-01T12:00:00Z".to_owned(),
        event_id: 4648,
        source_user: None, target_user: None, target_host: None,
        logon_type: None, auth_package: None, encryption_type: None,
    });
    assert_eq!(ev.timestamp(), "2024-06-01T12:00:00Z");
}

#[test]
fn evtx_event_event_id_accessor_returns_inner_event_id() {
    let ev = EvtxEvent::Defender(DefenderEvent {
        timestamp: String::new(),
        event_id: 1117,
        threat_name: None, severity: None, path: None,
        action_taken: None, process_name: None,
    });
    assert_eq!(ev.event_id(), 1117);
}
