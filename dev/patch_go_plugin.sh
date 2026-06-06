# from https://developers.mattermost.com/integrate/plugins/developer-workflow/
# patch_go_plugin.sh

GO_PLUGIN_PACKAGE_VERSION=$1

GO_PLUGIN_RPC_CLIENT_PATH=${GOPATH}/pkg/mod/github.com/hashicorp/go-plugin@${GO_PLUGIN_PACKAGE_VERSION}/rpc_client.go

echo "Patching $GO_PLUGIN_RPC_CLIENT_PATH for debugging Mattermost plugins"

if ! grep -q 'mux, err := yamux.Client(conn, nil)' "$GO_PLUGIN_RPC_CLIENT_PATH"; then
  echo "The file has already been patched or the target line was not found."
  exit 0
fi

#sudo sudo sed -i '' '/import (/a\
sed -i='' '/import (/a\
    "time"
' $GO_PLUGIN_RPC_CLIENT_PATH

#sudo sed -i '' '/mux, err := yamux.Client(conn, nil)/c\
sed -i='' '/mux, err := yamux.Client(conn, nil)/c\
    sessionConfig := yamux.DefaultConfig()\
    sessionConfig.EnableKeepAlive = false\
    sessionConfig.ConnectionWriteTimeout = time.Minute * 5\
    mux, err := yamux.Client(conn, sessionConfig)
' $GO_PLUGIN_RPC_CLIENT_PATH

echo "Patched go-plugin's rpc_client.go for debugging Mattermost plugins"
