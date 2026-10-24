def test_package_imports() -> None:
    import mcp_security_proxy
    import mcp_security_proxy.app
    import mcp_security_proxy.core.guard
    import mcp_security_proxy.core.identity
    import mcp_security_proxy.core.proxy
    import mcp_security_proxy.core.proxy.codec.base
    import mcp_security_proxy.core.proxy.routing
    import mcp_security_proxy.core.proxy.transport.base
    import mcp_security_proxy.sdk
    import mcp_security_proxy.services.log
    import mcp_security_proxy.services.policy

    assert mcp_security_proxy is not None
