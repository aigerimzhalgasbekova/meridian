package keystore

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Anchor persists the keystore's document generation outside the file the
// store writes. The generation inside the document authenticates records
// *within* one write, but travels with the file — so restoring an entire older
// keystore (records plus their generation) is internally consistent and would
// open cleanly. An anchor the file-write attacker cannot reach breaks that:
// the store refuses any document whose generation is below the anchored one,
// and advances the anchor after every successful persist.
//
// Implementations must not store the anchor on the same filesystem as the
// keystore; an anchor the same attacker can roll back detects nothing.
type Anchor interface {
	// Get returns the anchored generation. ok is false if the anchor has never
	// been set, which permits first-time initialization.
	Get(ctx context.Context) (gen int, ok bool, err error)
	// Set records gen as the current generation. Called after the document
	// carrying gen is durable, never before.
	Set(ctx context.Context, gen int) error
}

// SSMAnchor stores the generation in an AWS SSM parameter — outside the
// keystore's filesystem, writable only through the task role's IAM policy.
type SSMAnchor struct {
	client *ssm.Client
	name   string
}

// NewSSMAnchor anchors the generation in the named SSM parameter. The caller's
// IAM identity needs ssm:GetParameter and ssm:PutParameter on it.
func NewSSMAnchor(client *ssm.Client, name string) *SSMAnchor {
	return &SSMAnchor{client: client, name: name}
}

func (a *SSMAnchor) Get(ctx context.Context) (int, bool, error) {
	out, err := a.client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.name)})
	var notFound *types.ParameterNotFound
	if errors.As(err, &notFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("get %s: %w", a.name, err)
	}
	gen, err := strconv.Atoi(aws.ToString(out.Parameter.Value))
	if err != nil {
		return 0, false, fmt.Errorf("parameter %s does not hold a generation: %w", a.name, err)
	}
	return gen, true, nil
}

func (a *SSMAnchor) Set(ctx context.Context, gen int) error {
	// The generation is a counter, not a secret: parameter type String.
	_, err := a.client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(a.name),
		Value:     aws.String(strconv.Itoa(gen)),
		Type:      types.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("put %s: %w", a.name, err)
	}
	return nil
}
