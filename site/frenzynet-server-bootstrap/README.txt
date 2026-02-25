FrenzyNet Node Bootstrap

Run on new Linux server:

curl -fsSL https://frenzynets.com/frenzynet-server-bootstrap/install-frenzynet-node.sh | sudo bash -s -- --enroll-token 'PASTE_TOKEN' --name 'node-01'

This installer:
- installs curl/jq/wireguard-tools
- enrolls node into control plane
- sets heartbeat service + timer
