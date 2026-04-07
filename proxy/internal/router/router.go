package router

import (
	"go.uber.org/zap"
)

// Router traduz a label do nDPI para o endereço do honeypot correspondente.
type Router struct {
	routes       map[string]string
	defaultRoute string
	log          *zap.Logger
}

func New(routes map[string]string, defaultRoute string, log *zap.Logger) *Router {
	return &Router{
		routes:       routes,
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

// Routes retorna uma cópia das rotas configuradas.
func (r *Router) Routes() map[string]string {
	copy := make(map[string]string, len(r.routes))
	for k, v := range r.routes {
		copy[k] = v
	}
	return copy
}
