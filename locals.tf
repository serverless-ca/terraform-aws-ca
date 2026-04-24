locals {
  runtime = coalesce(var.runtime, format("python%s", regex("^\\d+\\.\\d+", file("${path.module}/python-version"))))
}
