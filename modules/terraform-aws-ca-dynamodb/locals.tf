locals {
  table_name = "${replace(title(replace(var.project, "-", " ")), " ", "")}CA${title(var.env)}"

  name_tag = {
    Name = "${var.project}-ca-${var.env}"
  }

  tags = merge(local.name_tag, var.tags)

}
