package router

import (
	"net"
	"strconv"
	"go.uber.org/zap"
)

// Router traduz a label do nDPI para o endereço do honeypot correspondente.
type Router struct {
	routes       map[string]string
	portRoutes  map[uint16]string
	defaultRoute string
	log          *zap.Logger
}

func New(routes map[string]string, defaultRoute string, log *zap.Logger) *Router {
	// Cria mappings de porta para honeypot
	portRoutes := make(map[uint16]string)
	for label, addr := range routes {
		// Extrai porta do addr (ex: "dionaea-svc.dpipot.svc.cluster.local:3306" -> 3306)
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		portNum, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			continue
		}
		portRoutes[uint16(portNum)] = addr
		log.Debug("mapeado porta para honeypot",
			zap.Uint16("port", uint16(portNum)),
			zap.String("honeypot", addr),
			zap.String("label", label),
		)
	}

	return &Router{
		routes:       routes,
		portRoutes:  portRoutes,
		defaultRoute: defaultRoute,
		log:          log,
	}
}

// Resolve retorna o endereço host:porta do honeypot para uma label nDPI.
func (r *Router) Resolve(ndpiLabel string) (addr string, matched bool) {
	if addr, ok := r.routes[ndpiLabel]; ok {
		r.log.Debug("rota encontrada",
			zap.String("label", ndpiLabel),
			zap.String("honeypot", addr),
		)
		return addr, true
	}

	r.log.Debug("rota não encontrada, usando padrão",
		zap.String("label", ndpiLabel),
		zap.String("honeypot", r.defaultRoute),
	)
	return r.defaultRoute, false
}

// ResolveByPort retorna o endereço do honeypot para uma porta específica.
func (r *Router) ResolveByPort(port uint16) string {
	if addr, ok := r.portRoutes[port]; ok {
		return addr
	}
	// Se não encontrou nas rotas por porta, retorna rota padrão
	r.log.Debug("porta não mapeada, usando rota padrao",
		zap.Uint16("port", port),
		zap.String("default", r.defaultRoute),
	)
	return r.defaultRoute
}

// Routes retorna uma cópia das rotas configuradas.
func (r *Router) Routes() map[string]string {
	copy := make(map[string]string, len(r.routes))
	for k, v := range r.routes {
		copy[k] = v
	}
	return copy
}
