package outbound

import (
	"context"
	"net"
	"net/url"
	"strings"

	"code.gitea.io/gitea/modules/hostmatcher"

	"github.com/sourcegraph/sourcegraph/internal/database"
	"github.com/sourcegraph/sourcegraph/internal/database/basestore"
	"github.com/sourcegraph/sourcegraph/internal/encryption"
	"github.com/sourcegraph/sourcegraph/internal/encryption/keyring"
	"github.com/sourcegraph/sourcegraph/lib/errors"
)

type OutboundWebhookService interface {
	// EnqueueWebhook creates an outbound webhook job for the given webhook
	// event type, optional scope, and payload. In the normal course of events,
	// this will be picked up by the outbound webhook sender worker in short
	// order, and the webhook will be dispatched to any registered webhooks that
	// match the given type and scope.
	Enqueue(ctx context.Context, eventType string, scope *string, payload []byte) error
}

type outboundWebhookService struct {
	store database.OutboundWebhookJobStore
}

// NewOutboundWebhookService instantiates a new outbound webhook service. If key
// is nil, then the outbound webhook key will be used from the default keyring.
func NewOutboundWebhookService(db basestore.ShareableStore, key encryption.Key) OutboundWebhookService {
	if key == nil {
		key = keyring.Default().OutboundWebhookKey
	}

	return &outboundWebhookService{
		store: database.OutboundWebhookJobsWith(db, key),
	}
}

func (s *outboundWebhookService) Enqueue(
	ctx context.Context,
	eventType string,
	scope *string,
	payload []byte,
) error {
	if _, err := s.store.Create(ctx, eventType, scope, payload); err != nil {
		return errors.Wrap(err, "creating webhook job")
	}

	return nil
}

var errIllegalAddr = errors.New("Address must not be private, link-local or loopback")

// CheckAddress validates the intended destination address for a webhook, checking that
// it's not invalid, local, a bad IP, or anything else.
func CheckAddress(address string) error {
	u, uErr := url.Parse(address)
	if uErr != nil || !strings.HasPrefix(u.Scheme, "http") {
		return errors.New("Could not parse address")
	}
	// This will validate if the IP address is external. Private, loopback and other
	// non-external IP addresses are not allowed.
	hostAllowList := hostmatcher.ParseHostMatchList("", hostmatcher.MatchBuiltinExternal)

	var addrs []string
	var err error

	ip := net.ParseIP(u.Hostname())

	if ip != nil {
		if isIllegalIp(ip, hostAllowList) {
			return errIllegalAddr
		}
	} else {
		addrs, err = net.LookupHost(u.Hostname())

		if err != nil || len(addrs) == 0 {
			return errors.New("Could not resolve hostname")
		}
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil {
				if isIllegalIp(ip, hostAllowList) {
					return errIllegalAddr
				}
			}
		}
	}

	return nil
}

func isIllegalIp(ip net.IP, hostAllowList *hostmatcher.HostMatchList) bool {
	// if we do not match the IP address, it's not in the allow list
	return !hostAllowList.MatchIPAddr(ip)
}
