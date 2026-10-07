#!/bin/sh
# Which peers may tell nginx who the client is (X-Forwarded-For), so the API's login throttles and
# audit log see each client rather than one shared address. From TRUSTED_PROXIES, comma-separated:
#   gateway   this container's default gateway: connections through a port Docker publishes on the
#             host (a reverse proxy on the host, behind the loopback bind) come from there
#   addresses or CIDRs, e.g. a reverse proxy container's network
#   none      trust nobody: every client is the address that connected
# Default: gateway. If the port is published to the network without a reverse proxy, set none, or
# clients could name any address they like.
set -eu

conf=/etc/nginx/conf.d/00-real-ip.conf
trusted=${TRUSTED_PROXIES:-gateway}
lines=""
if ! (: >"$conf") 2>/dev/null; then
    echo "$0: can't write $conf (read-only?): no proxy is trusted, every client is the peer" >&2
    exit 0
fi

for entry in $(echo "$trusted" | tr ',' ' '); do
    case "$entry" in
        none) ;;
        gateway)
            gw=$(ip -4 route show default 2>/dev/null | awk '{ print $3; exit }')
            if [ -n "$gw" ]; then
                lines="${lines}set_real_ip_from $gw;
"
            else
                echo "$0: TRUSTED_PROXIES: no default gateway found" >&2
            fi
            ;;
        *[!0-9A-Fa-f:./]*)
            echo "$0: TRUSTED_PROXIES: '$entry' is not an address, a CIDR, gateway or none" >&2
            exit 1
            ;;
        *)
            lines="${lines}set_real_ip_from $entry;
"
            ;;
    esac
done

{
    echo "# Written by $0 at start, from TRUSTED_PROXIES=$trusted"
    if [ -n "$lines" ]; then
        echo "real_ip_header X-Forwarded-For;"
        echo "real_ip_recursive on;"
        printf '%s' "$lines"
    fi
} >"$conf"
echo "$0: trusting X-Forwarded-For from: $(echo "$lines" | awk '{ printf "%s ", $2 }' | tr -d ';')"
