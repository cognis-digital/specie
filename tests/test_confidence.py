from specie.confidence import band, combine_supporting


def test_noisy_or_two_equal():
    assert abs(combine_supporting([0.5, 0.5]) - 0.75) < 1e-9


def test_noisy_or_empty_is_zero():
    assert combine_supporting([]) == 0.0


def test_noisy_or_monotonic():
    assert combine_supporting([0.6]) < combine_supporting([0.6, 0.3])


def test_bands():
    assert band(0.95) == "HIGH"
    assert band(0.6) == "MODERATE"
    assert band(0.1) == "LOW"
    assert band(0.0) == "NONE"
