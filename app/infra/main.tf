resource "google_service_account" "widgets" {
  account_id   = "widgets-api"
  display_name = "Widgets API"
}

resource "google_storage_bucket" "widgets_assets" {
  name                        = "widgets-assets-example"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.widgets_assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
