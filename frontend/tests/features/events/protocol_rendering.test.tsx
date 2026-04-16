import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import EventDetailsPanel from "@/features/events/components/EventDetailsPanel";
import EventsTable from "@/features/events/components/EventsTable";
import { getEventProtocolIntel } from "@/features/events/lib/protocol";
import type { NetEvent } from "@/features/events/types";

function makeEvent(input: Partial<NetEvent>): NetEvent {
  return {
    id: 1,
    agent_id: "agent-1",
    event_type: "flow",
    schema_version: 1,
    timestamp: "2026-04-12T10:00:00Z",
    extra: {},
    ...input,
  };
}

describe("event protocol intel rendering", () => {
  it("extracts HTTP protocol metadata with a compact hint", () => {
    const event = makeEvent({
      proto: "tcp",
      extra: {
        app_proto: "http",
        app_proto_reason: "parsed_http",
        app_proto_conf_band: "high",
        http_method: "GET",
        http_host: "api.example.com",
      },
    });

    expect(getEventProtocolIntel(event)).toMatchObject({
      transportProto: "tcp",
      appProto: "http",
      appProtoReason: "parsed_http",
      appProtoConfBand: "high",
      httpMethod: "GET",
      httpHost: "api.example.com",
      hint: "GET api.example.com",
      hasProtocolIntel: true,
    });
  });

  it("extracts DNS protocol metadata", () => {
    const event = makeEvent({
      proto: "udp",
      extra: {
        app_proto: "dns",
        dns_qname: "login.example.org",
        dns_qtype: "A",
        dns_rcode: "NOERROR",
      },
    });

    expect(getEventProtocolIntel(event)).toMatchObject({
      transportProto: "udp",
      appProto: "dns",
      dnsQname: "login.example.org",
      dnsQtype: "A",
      dnsRcode: "NOERROR",
      hint: "login.example.org",
    });
  });

  it("preserves TLS and QUIC metadata without faking HTTP", () => {
    const tlsEvent = makeEvent({
      proto: "tcp",
      extra: {
        app_proto: "tls",
        tls_sni: "login.example.com",
        tls_alpn_first: "h2",
        ja3: "ja3-fingerprint",
        ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
        ja4_ptype: "t",
      },
    });
    const quicEvent = makeEvent({
      proto: "udp",
      extra: {
        app_proto: "quic",
        tls_sni: "edge.example.net",
        tls_alpn_first: "h3",
        ja4: "q13d0310h3_55b375c5d22e_710ed5d8058f",
        ja4_ptype: "q",
      },
    });

    expect(getEventProtocolIntel(tlsEvent)).toMatchObject({
      appProto: "tls",
      tlsSni: "login.example.com",
      tlsAlpnFirst: "h2",
      ja3: "ja3-fingerprint",
      ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
      ja4Ptype: "t",
      httpHost: "",
      httpMethod: "",
    });
    expect(getEventProtocolIntel(quicEvent)).toMatchObject({
      transportProto: "udp",
      appProto: "quic",
      tlsSni: "edge.example.net",
      tlsAlpnFirst: "h3",
      ja4: "q13d0310h3_55b375c5d22e_710ed5d8058f",
      ja4Ptype: "q",
      hint: "edge.example.net",
    });
  });

  it("renders application and transport protocol in the events table", () => {
    const markup = renderToStaticMarkup(
      <EventsTable
        rows={[
          makeEvent({
            proto: "tcp",
            extra: {
              app_proto: "http",
              http_method: "GET",
              http_host: "portal.example.com",
            },
          }),
        ]}
        selectedId={null}
      />
    );

    expect(markup).toContain("Protocol");
    expect(markup).toContain("HTTP");
    expect(markup).toContain("over TCP");
    expect(markup).toContain("GET portal.example.com");
  });

  it("falls back to transport-only protocol rendering when app intel is missing", () => {
    const markup = renderToStaticMarkup(
      <EventsTable
        rows={[
          makeEvent({
            proto: "udp",
            extra: {
              reason: "transport_only",
            },
          }),
        ]}
        selectedId={null}
      />
    );

    expect(markup).toContain("UDP");
    expect(markup).not.toContain("over UDP");
    expect(markup).not.toContain("HTTP");
    expect(markup).not.toContain("DNS");
  });

  it("renders protocol intel outside pure l7_flow events", () => {
    const markup = renderToStaticMarkup(
      <EventDetailsPanel
        event={makeEvent({
          event_type: "alert",
          proto: "tcp",
          extra: {
            app_proto: "tls",
            app_proto_reason: "agent_evidence",
            app_proto_conf_band: "high",
            tls_sni: "login.example.com",
            tls_alpn_first: "h2",
            ja3: "ja3-fingerprint",
            ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
            ja4_ptype: "t",
          },
        })}
      />
    );

    expect(markup).toContain("Protocol intel");
    expect(markup).toContain("app_proto");
    expect(markup).toContain("TLS");
    expect(markup).toContain("transport_proto");
    expect(markup).toContain("TCP");
    expect(markup).toContain("tls_sni");
    expect(markup).toContain("login.example.com");
    expect(markup).toContain("ja4");
    expect(markup).toContain("t13d1516h2_8daaf6152771_e5627efa2ab1");
  });
});
