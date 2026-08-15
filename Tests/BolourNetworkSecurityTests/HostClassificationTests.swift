import Testing
@testable import BolourNetworkSecurity

@Suite("UnvalidatedTrustOverride host classification")
struct HostClassificationTests {

    @Test(
        "accepted local-development hosts",
        arguments: [
            "localhost", "LOCALHOST", "printer.local", "My-Mac.local",
            "127.0.0.1", "127.5.5.5",
            "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "::1",
        ]
    )
    func acceptedHosts(_ host: String) {
        #expect(UnvalidatedTrustOverride.isLocalDevelopmentHost(host))
    }

    @Test(
        "refused non-local hosts",
        arguments: [
            "example.com", "api.example.com", "blursecurity.test",
            "8.8.8.8",           // public IPv4
            "172.32.0.1",        // just outside the RFC 1918 172.16.0.0/12 block
            "169.254.1.1",       // link-local, not in our accepted set
            "2001:db8::1",       // public-shaped IPv6
            "",
        ]
    )
    func refusedHosts(_ host: String) {
        #expect(!UnvalidatedTrustOverride.isLocalDevelopmentHost(host))
    }

    @Test("construction succeeds for an all-local host set")
    func constructionSucceeds() throws {
        let override = try UnvalidatedTrustOverride(forLocalDevelopmentHosts: ["localhost", "127.0.0.1"])
        #expect(override.hosts == ["localhost", "127.0.0.1"])
    }

    @Test("construction refuses as soon as one host is not local")
    func constructionRefusesPublicHost() {
        #expect(throws: PinningEnforcementError.self) {
            _ = try UnvalidatedTrustOverride(forLocalDevelopmentHosts: ["localhost", "example.com"])
        }
    }

    @Test("the refusal names the offending host")
    func refusalNamesHost() {
        do {
            _ = try UnvalidatedTrustOverride(forLocalDevelopmentHosts: ["evil.example.com"])
            Issue.record("expected overrideHostNotLocal to be thrown")
        } catch PinningEnforcementError.overrideHostNotLocal(let host) {
            #expect(host == "evil.example.com")
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }
}
