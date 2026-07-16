use crate::threat_intel::{
    profile::{MalwareClass, MalwareProfile, ProfileSignal},
    signals::{
        NETWORK_STRATUM_CONNECTION, NETWORK_STRATUM_LISTEN, PROCESS_ANOMALOUS_THREAD_COUNT,
        PROCESS_HIDDEN_FROM_PS, PROCESS_MASQUERADE, PROCESS_THREAD_MINER_GENERIC,
        PROCESS_THREAD_MINER_XMRIG, SYSTEM_CPU_ANOMALY_HIGH,
    },
};

pub static XMRIG: MalwareProfile = MalwareProfile {
    id: "xmrig",
    family: "XMRig",
    aliases: &["xmr-stak", "cryptonight-miner"],
    description: "Open-source Monero/crypto miner. Often deployed by rootkit-concealed \
                  threat actors. Identified by libuv worker thread names and Stratum \
                  protocol connections. Frequently disguised with a system process name.",
    malware_class: MalwareClass::CryptoMiner,
    mitre_techniques: &["T1496", "T1036.005"],
    signals: &[
        ProfileSignal {
            id: PROCESS_THREAD_MINER_XMRIG,
            weight: 40,
            required: false,
        },
        ProfileSignal {
            id: PROCESS_THREAD_MINER_GENERIC,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: NETWORK_STRATUM_CONNECTION,
            weight: 30,
            required: false,
        },
        ProfileSignal {
            id: NETWORK_STRATUM_LISTEN,
            weight: 20,
            required: false,
        },
        ProfileSignal {
            id: SYSTEM_CPU_ANOMALY_HIGH,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: PROCESS_MASQUERADE,
            weight: 10,
            required: false,
        },
        ProfileSignal {
            id: PROCESS_ANOMALOUS_THREAD_COUNT,
            weight: 15,
            required: false,
        },
        ProfileSignal {
            id: PROCESS_HIDDEN_FROM_PS,
            weight: 20,
            required: false,
        },
    ],
    exclusions: &[],
    class_threshold: 30,
    probable_threshold: 55,
    confirmed_threshold: 75,
};

#[cfg(test)]
mod tests {
    use super::XMRIG;
    use crate::threat_intel::{
        engine::{score_against_profile, DetectedSignal},
        profile::Classification,
        signals::*,
    };

    fn sigs(ids: &[&'static str]) -> Vec<DetectedSignal> {
        ids.iter()
            .map(|&id| DetectedSignal {
                id,
                confidence: 1.0,
                evidence: String::new(),
            })
            .collect()
    }

    #[test]
    fn xmrig_thread_signal_alone_reaches_class_threshold() {
        let s = sigs(&[PROCESS_THREAD_MINER_XMRIG]);
        let m = score_against_profile(&s, &XMRIG);
        assert!(
            m.score >= XMRIG.class_threshold,
            "score {} < class_threshold {}",
            m.score,
            XMRIG.class_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::ClassMatch);
    }

    #[test]
    fn xmrig_thread_plus_stratum_reaches_probable() {
        let s = sigs(&[PROCESS_THREAD_MINER_XMRIG, NETWORK_STRATUM_CONNECTION]);
        let m = score_against_profile(&s, &XMRIG);
        assert!(
            m.score >= XMRIG.probable_threshold,
            "score {} < probable_threshold {}",
            m.score,
            XMRIG.probable_threshold // cov:unreachable: assert failure-message arg, evaluated only on assertion failure
        );
        assert!(m.classification >= Classification::Probable);
    }
}
