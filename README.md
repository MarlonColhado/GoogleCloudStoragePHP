# GoogleCloudStoragePHP

> Lighter and easier to use library

## Installation

```php
require 'GoogleCloudStorage.class.php';
```

## Sample Usage
### Google Cloud Authentication
```php
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
```

### Change to another bucket
```php
//If you need to change the bucket name
$GoogleCloud->Bucket("CHANGE TO ANOTHER BUCKET NAME");
```

### List all objects
```php
//List all objects
$objects = $GoogleCloud->ListAllObjects();
print_r($objects);

//List all objects from a specific folder
$objects = $GoogleCloud->ListAllObjects("folder");
print_r($objects);
```

### List objects with pagination
```php
//List objects with pagination
$objects = $GoogleCloud->ListObjects(1, 5); //parameters: page, maxResults
print_r($objects);

//List objects with pagination from a specific folder
$objects = $GoogleCloud->ListObjects(2, 5, "folder); //parameters: page, maxResults, folder
print_r($objects);
```

### Upload objects
```php
//Parameters: rawFileData [file_get_contents], fileName
$object = $GoogleCloud->UploadObject($fileContent, "image.jpg");

//Upload object to specific folder - Parameters: rawFileData [file_get_contents], fileName, folder
$object = $GoogleCloud->UploadObject($fileContent, "image.jpg", "folder");
```
