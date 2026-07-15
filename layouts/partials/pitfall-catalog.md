{{- $site := .Site -}}
{{- $nested := .Nested -}}
{{- $heading := cond $nested "###" "##" -}}
{{- $allPages := where $site.RegularPages "Section" "pitfalls" -}}
{{- $intros := sort (where $allPages "Params.intro" true) ".Params.order" -}}
{{- $pitfalls := where (where $allPages "Params.intro" "ne" true) "Params.hidden" "ne" true -}}
{{- $bugMap := partial "bug-map.html" $site -}}
{{ range $category := $intros }}
{{- $categoryPitfalls := sort (where $pitfalls "Params.class" $category.Params.class) ".Params.order" }}

{{ $heading }} [{{ $category.Title }}]({{ printf "pitfalls/classes/%s/llms.txt" $category.File.BaseFileName | absURL }})

{{ $category.RawContent | replaceRE `(?s)<!--.*?-->` "" | strings.TrimSpace }}
{{ range $pf := $categoryPitfalls }}
{{- $related := slice -}}
{{- range $id := $pf.Params.bugs -}}
    {{- if isset $bugMap $id -}}
        {{- $bug := $site.GetPage (printf "/bugs/%s" $id) -}}
        {{- with $bug -}}
            {{- $related = $related | append (printf "[%s](%s)" .Title (printf "bugs/%s/llms.txt" $id | absURL)) -}}
        {{- end -}}
    {{- end -}}
{{- end }}

- [{{ $pf.Title }}]({{ printf "pitfalls/%s/llms.txt" $pf.File.BaseFileName | absURL }}) — Primitives: {{ delimit $pf.Params.primitives ", " }}{{ if gt (len $related) 0 }}. Related bugs: {{ delimit $related "; " }}{{ end }}
{{- end }}
{{- end }}
