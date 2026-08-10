from ua_parser import parse


def get_device_name(user_agent: str | None) -> str | None:

    if not user_agent:
        return None

    parsed = parse(user_agent)

    browser = parsed.user_agent.family
    operating_system = parsed.os.family

    device = None

    if parsed.device:
        device = parsed.device.family

    if browser and operating_system:
        return f"{browser} on {operating_system}"

    if browser:
        return browser

    if operating_system:
        return operating_system

    if device and device != "Other":
        return device

    return "Unknown Device"