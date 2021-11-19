# GoogleCloudStoragePHP

> Idiomatic PHP client for [Cloud Storage](https://cloud.google.com/storage/).Lighter and easier to use library

### Sample Usage

```php
require 'GoogleCloudStorage.class.php';

//Google Cloud - Service Account Generated Key
$key = '{
    "type": "service_account",
    "project_id": "projectid [...]",
    "private_key_id": "3b983 [...] c65aa58b2b",
    "private_key": "",
    "client_email": " clientemail [...]",
    "client_id": "1139 [...] 5434",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/ [...]"
}';

//Generate credentials/authorization
$GoogleCloud = new GoogleCloudStorage($key, "BUCKET NAME");

//If you need to change the bucket name
$GoogleCloud->Bucket("CHANGE TO ANOTHER BUCKET NAME");

//List all objects
$objects = $GoogleCloud->ListObjects();
print_r($objects);

//List objects from a specific folder
$objects = $GoogleCloud->ListObjects("folder");
print_r($objects);

//Upload object (fileContent is the raw file data) [file_get_contents]
$object = $GoogleCloud->UploadObject($fileContent, "image.jpg");
print_r($object);

//Upload object to specific folder (fileContent is the raw file data) [file_get_contents]
$object = $GoogleCloud->UploadObject($fileContent, "image.jpg", "folder");
```
