# acm — conventions

- **ACM ConfigurationPolicy Go template escaping** — PrometheusRule annotations with `{{ $labels }}` syntax require both `hub-templates: "raw"` and `disable-templates: "true"` annotations on the ConfigurationPolicy metadata
