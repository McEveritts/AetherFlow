import os

path = 'backend/api/marketplace.go'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

target = "pkgs := services.GetPackages()\n\n\tvar apps []App"
target_rn = "pkgs := services.GetPackages()\r\n\r\n\tvar apps []App"
repl = """pkgs := services.GetPackages()
\tif pkgs == nil {
\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load package catalog configuration"})
\t\treturn
\t}

\tapps := []App{}"""

changed = False
if target_rn in text:
    text = text.replace(target_rn, repl.replace('\n', '\r\n'))
    changed = True
elif target in text:
    text = text.replace(target, repl)
    changed = True

if changed:
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(text)
    print("Success")
else:
    print("Failed to find target text")
