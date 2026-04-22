from redscan.models import DiscoveryConfig
from redscan.smart_scan import AdaptiveRateController


def test_controller_sets_fallback_base_for_short_warmup_scans() -> None:
    cfg = DiscoveryConfig(
        rtt_base_warmup_samples=5,
        initial_rate=100,
        r_min=10,
        r_max=2000,
    )
    ctl = AdaptiveRateController(cfg)
    ctl.calibration_update(25.0)

    # Warmup is not complete yet, but control update should still establish
    # a usable baseline so the controller can adapt during short scans.
    ctl.control_update()
    assert ctl.base_rtt_ms is not None
    assert ctl.filtered_rtt_ms is not None


def test_aimd_backoff_reduces_rate_at_loss_threshold() -> None:
    cfg = DiscoveryConfig(
        initial_rate=200,
        r_min=10,
        r_max=2000,
        loss_threshold=2,
        aimd_beta=0.5,
    )
    ctl = AdaptiveRateController(cfg)
    ctl.calibration_update(20.0)
    ctl.calibration_update(20.0)

    ctl.register_timeout()
    ctl.register_timeout()
    ctl.control_update()

    assert ctl.rate == 100.0

