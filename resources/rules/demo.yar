rule SentinelAV_Harmless_Demo
{
    meta:
        description = "Harmless SentinelAV demonstration marker"
    strings:
        $marker = "SENTINELAV_DEMO_THREAT_7C23A"
    condition:
        $marker
}
