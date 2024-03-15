variable "project" {
  description = "abbreviation for the project, forms first part of resource names"
}

variable "env" {
  description = "Environment name, e.g. dev"
}

variable "purpose" {
  description = "purpose of Scheduler"
  default     = "ca"
}

variable "role_arn" {
  description = "IAM role to be assumed by scheduler"
}

variable "target_arn" {
  description = "ARN of target to be triggered"
}

variable "schedule_expression" {
  description = "Schedule in supported format"
}

variable "group_name" {
  description = "EventBridge Group name"
  default     = "default"
}
