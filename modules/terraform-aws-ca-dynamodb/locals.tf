locals {
  table_name = "${replace(title(replace(var.project, "-", " ")), " ", "")}CA${title(var.env)}"
}
