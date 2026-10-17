def test_package_imports() -> None:
    import mcp_security_proxy
    import mcp_security_proxy.app
    import mcp_security_proxy.core.proxy
    import mcp_security_proxy.core.proxy.codec.base
    import mcp_security_proxy.core.proxy.routing
    import mcp_security_proxy.core.proxy.transport.base

    assert mcp_security_proxy is not None
