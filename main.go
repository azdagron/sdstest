package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

func main() {
	disabledFlag := flag.Bool("disable", false, "whether or not to disable SPIFFE Cert Validation extension; only used if -set-metadata is also set")
	setMetadataFlag := flag.Bool("set-metadata", false, "send request metadata")
	resourceNamesFlag := flag.String("resources", "spiffe://example.org", "comma separated list of the resource names to retrieve")
	minorVersionFlag := flag.Int("minor-version", 18, "User agent minor version to use (i.e. Envoy minor version number)")
	targetFlag := flag.String("target", "unix:///tmp/spire-agent/public/api.sock", "unix URI to the SDS target (i.e. SPIRE agent)")
	rawFlag := flag.Bool("raw", false, "whether or not to print the raw response")
	flag.Parse()

	conn, err := grpc.DialContext(
		context.Background(),
		*targetFlag,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	checkErr(err)
	defer conn.Close()

	metadata := make(map[string]interface{})
	if *setMetadataFlag {
		metadata["disable_spiffe_cert_validation"] = *disabledFlag
	}

	nodeMetadata, err := structpb.NewStruct(metadata)
	checkErr(err)

	client := secret_v3.NewSecretDiscoveryServiceClient(conn)
	resp, err := client.FetchSecrets(context.Background(), &discovery_v3.DiscoveryRequest{
		Node: &core_v3.Node{
			Metadata: nodeMetadata,
			UserAgentVersionType: &core_v3.Node_UserAgentBuildVersion{
				UserAgentBuildVersion: &core_v3.BuildVersion{
					Version: &type_v3.SemanticVersion{
						MajorNumber: 1,
						MinorNumber: uint32(*minorVersionFlag),
					},
				},
			},
		},
		ResourceNames: strings.Split(*resourceNamesFlag, ","),
	})
	checkErr(err)

	if *rawFlag {
		jsonData, err := protojson.MarshalOptions{Indent: "    "}.Marshal(resp)
		checkErr(err)
		fmt.Println(string(jsonData))
	} else {
		printResources(resp.Resources)
	}
}

func printResources(resources []*anypb.Any) {
	for i, resource := range resources {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("[RESOURCE %d]\n", i)
		printResource(resource)
	}
}

func printResource(resource *anypb.Any) {
	switch resource.TypeUrl {
	case "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret":
		printSecret(resource.Value)
	default:
		fmt.Println("unknown resource type:", resource.TypeUrl)
	}
}

func printSecret(secretValue []byte) {
	secret := new(tls_v3.Secret)
	if err := proto.Unmarshal(secretValue, secret); err != nil {
		fmt.Printf("failed to unmarshal secret: %v\n", err)
		return
	}
	fmt.Println("    Name:", secret.Name)
	fmt.Printf("    Type: ")
	switch secret := secret.Type.(type) {
	case *tls_v3.Secret_TlsCertificate:
		printTLSCertificate(secret.TlsCertificate)
	case *tls_v3.Secret_ValidationContext:
		printValidationContext(secret.ValidationContext)
	default:
		fmt.Println("unknown")
	}
}

func printTLSCertificate(tlsCertificate *tls_v3.TlsCertificate) {
	fmt.Println("TLS Certificate")
}

func printValidationContext(validationContext *tls_v3.CertificateValidationContext) {
	fmt.Println("Validation Context")
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
