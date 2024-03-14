### 1. Initialize Go module 

mkdir envoy-wasm-filter
cd envoy-wasm-filter
go mod init envoy-wasm-filter

### 2. Write the filter logic using tetrate SDK and write JWT validation login

### 3. Compile to WASM using TinyGo
tinygo build -o filter.wasm -target=wasi main.go

### 4. Configure envoy to use the WASM filter

