import os
import shutil
from io import BytesIO

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.utils.encoding import force_text, smart_str

try:
    from botocore.session import Session as CoreSession
    from botocore.vendored.requests.packages.urllib3.fields import guess_content_type
    from boto3.core.exceptions import ServerError
    from boto3.core.session import Session
    from boto3.s3.resources import S3ObjectCustomizations
except ImportError:
    raise ImproperlyConfigured("Could not load Boto3's S3 bindings.\n"
                               "See https://github.com/boto/boto3")

ACCESS_KEY_NAME = getattr(
    settings,
    'AWS_S3_ACCESS_KEY_ID',
    getattr(settings, 'AWS_ACCESS_KEY_ID', None))
SECRET_KEY_NAME = getattr(
    settings,
    'AWS_S3_SECRET_ACCESS_KEY',
    getattr(settings, 'AWS_SECRET_ACCESS_KEY', None))
STORAGE_BUCKET_NAME = getattr(settings, 'AWS_STORAGE_BUCKET_NAME', None)
AUTO_CREATE_BUCKET = getattr(settings, 'AWS_AUTO_CREATE_BUCKET', False)
DEFAULT_ACL = getattr(settings, 'AWS_DEFAULT_ACL', 'public-read')
BUCKET_ACL = getattr(settings, 'AWS_BUCKET_ACL', DEFAULT_ACL)
QUERYSTRING_AUTH = getattr(settings, 'AWS_QUERYSTRING_AUTH', True)
QUERYSTRING_EXPIRE = getattr(settings, 'AWS_QUERYSTRING_EXPIRE', 3600)
STORAGE_CLASS = getattr(settings, 'AWS_STORAGE_CLASS', 'STANDARD')
LOCATION = getattr(settings, 'AWS_LOCATION', '')
ENCRYPTION = getattr(settings, 'AWS_S3_ENCRYPTION', False)
CUSTOM_DOMAIN = getattr(settings, 'AWS_S3_CUSTOM_DOMAIN', None)
SECURE_URLS = getattr(settings, 'AWS_S3_SECURE_URLS', True)
FILE_NAME_CHARSET = getattr(settings, 'AWS_S3_FILE_NAME_CHARSET', 'utf-8')
FILE_OVERWRITE = getattr(settings, 'AWS_S3_FILE_OVERWRITE', True)
FILE_BUFFER_SIZE = getattr(settings, 'AWS_S3_FILE_BUFFER_SIZE', 5242880)
IS_GZIPPED = getattr(settings, 'AWS_IS_GZIPPED', False)
PRELOAD_METADATA = getattr(settings, 'AWS_PRELOAD_METADATA', False)
GZIP_CONTENT_TYPES = getattr(settings, 'GZIP_CONTENT_TYPES', (
    'text/css',
    'application/javascript',
    'application/x-javascript',
))
URL_PROTOCOL = getattr(settings, 'AWS_S3_URL_PROTOCOL', 'http:')

# Backward-compatibility: given the anteriority of the SECURE_URL setting
# we fall back to https if specified in order to avoid the construction
# of unsecure urls.
if SECURE_URLS:
    URL_PROTOCOL = 'https:'

if IS_GZIPPED:
    from gzip import GzipFile


def safe_join(base, *paths):
    """
    A version of django.utils._os.safe_join for S3 paths.

    Joins one or more path components to the base path component
    intelligently. Returns a normalized version of the final path.

    The final path must be located inside of the base path component
    (otherwise a ValueError is raised).

    Paths outside the base path indicate a possible security
    sensitive operation.
    """
    from urllib.parse import urljoin
    base_path = force_text(base)
    base_path = base_path.rstrip('/')
    paths = [force_text(p) for p in paths]

    final_path = base_path
    for path in paths:
        final_path = urljoin(final_path.rstrip('/') + "/", path.rstrip("/"))

    # Ensure final_path starts with base_path and that the next character after
    # the final path is '/' (or nothing, in which case final_path must be
    # equal to base_path).
    base_path_len = len(base_path)
    if (not final_path.startswith(base_path) or
            final_path[base_path_len:base_path_len + 1] not in ('', '/')):
        raise ValueError('the joined path is located outside of the base path'
                         ' component')

    return final_path.lstrip('/')


class S3BotoStorage(Storage):
    """
    Amazon Simple Storage Service using Boto

    This storage backend supports opening files in read or write
    mode and supports streaming(buffering) data in chunks to S3
    when writing.
    """
    connection_response_error = ServerError

    def __init__(self, bucket=STORAGE_BUCKET_NAME, access_key=None,
            secret_key=None, bucket_acl=BUCKET_ACL, acl=DEFAULT_ACL,
            gzip=IS_GZIPPED,
            gzip_content_types=GZIP_CONTENT_TYPES,
            querystring_auth=QUERYSTRING_AUTH,
            querystring_expire=QUERYSTRING_EXPIRE,
            storage_class=STORAGE_CLASS,
            encryption=ENCRYPTION,
            custom_domain=CUSTOM_DOMAIN,
            secure_urls=SECURE_URLS,
            url_protocol=URL_PROTOCOL,
            location=LOCATION,
            file_name_charset=FILE_NAME_CHARSET,
            preload_metadata=PRELOAD_METADATA):
        self.bucket_acl = bucket_acl
        self.bucket_name = bucket
        self.acl = acl
        self.preload_metadata = preload_metadata
        self.gzip = gzip
        self.gzip_content_types = gzip_content_types
        self.querystring_auth = querystring_auth
        self.querystring_expire = querystring_expire
        self.storage_class = storage_class
        self.encryption = encryption
        self.custom_domain = custom_domain
        self.secure_urls = secure_urls
        self.url_protocol = url_protocol
        self.location = location or ''
        self.location = self.location.lstrip('/')
        self.file_name_charset = file_name_charset
        self._entries = {}
        if not access_key and not secret_key:
            access_key, secret_key = self._get_access_keys()
        self.session = Session(session=CoreSession(session_vars={
            'ACCESS_KEY_NAME': access_key,
            'SECRET_KEY_NAME': secret_key,
        }))
        self.connection = self.session.connect_to('s3')
        # Based on boto3.s3.resources using custom session.
        self.BucketCollection = self.session.get_collection(
            's3',
            'BucketCollection')
        self.S3ObjectCollection = self.session.get_collection(
            's3',
            'S3ObjectCollection')
        self.Bucket = self.session.get_resource('s3', 'Bucket')
        self.S3Object = self.session.get_resource(
            's3',
            'S3Object',
            base_class=S3ObjectCustomizations)

        # Keep it on the collection, not the session-wide cached version.
        self.S3ObjectCollection.change_resource(self.S3Object)

    @property
    def bucket(self):
        """
        Get the current bucket. If there is no current bucket object
        create it.
        """
        if not hasattr(self, '_bucket'):
            self._bucket = self._get_or_create_bucket(self.bucket_name)
        return self._bucket

    @property
    def entries(self):
        """
        Get the locally cached files for the bucket.
        """
        if self.preload_metadata and not self._entries:
            self._entries = dict((self._decode_name(entry.key), self._set_identifier(entry))
                                for entry in self.bucket.objects.each())
        return self._entries

    def get_s3object(self, name, use_cache=True):
        """
        Get an s3 object from the bucket.
        """
        if use_cache and self.entries:
            entry = self.entries.get(name)
            if entry:
                return entry
        try:
            entry = self.bucket.objects.each(prefix=self._encode_name(name))[0]
        except IndexError:
            return None
        self._set_identifier(entry)
        return entry

    def _set_identifier(self, obj):
        """Set the bucket identifier on the objects."""
        ids = obj.get_identifiers()
        ids['bucket'] = self.bucket_name
        obj.set_identifiers(ids)
        return obj

    def _get_access_keys(self):
        """
        Gets the access keys to use when accessing S3. If none
        are provided to the class in the constructor or in the
        settings then get them from the environment variables.
        """
        access_key = ACCESS_KEY_NAME
        secret_key = SECRET_KEY_NAME
        if (access_key or secret_key) and (not access_key or not secret_key):
            # TODO: this seems to be broken
            access_key = os.environ.get(ACCESS_KEY_NAME)
            secret_key = os.environ.get(SECRET_KEY_NAME)

        if access_key and secret_key:
            # Both were provided, so use them
            return access_key, secret_key

        return None, None

    def _get_or_create_bucket(self, name):
        """Retrieves a bucket if it exists, otherwise creates it."""
        bucket = self.Bucket(bucket=name)
        try:
            # Raise an error if the bucket does not exist.
            # bucket.get()  # This alwasy returns ''
            bucket.get_acl()
        except self.connection_response_error:
            if not AUTO_CREATE_BUCKET:
                raise ImproperlyConfigured("Bucket specified by "
                    "AWS_STORAGE_BUCKET_NAME does not exist. "
                    "Buckets can be automatically created by setting "
                    "AWS_AUTO_CREATE_BUCKET=True")
            self.BucketCollection().create(bucket=name)
            bucket.put_acl(acl=self.bucket_acl)
        return bucket

    def _construct_object(self, key):
        return self.S3Object(
            bucket=self.bucket_name,
            key=key
        )

    def _clean_name(self, name):
        """
        Cleans the name so that Windows style paths work
        """
        # Useful for windows' paths
        return os.path.normpath(name).replace('\\', '/')

    def _normalize_name(self, name):
        """
        Normalizes the name so that paths like /path/to/ignored/../something.txt
        work. We check to make sure that the path pointed to is not outside
        the directory specified by the LOCATION setting.
        """
        try:
            return safe_join(self.location, name)
        except ValueError:
            raise SuspiciousOperation("Attempted access to '%s' denied." %
                                      name)

    def _encode_name(self, name):
        return smart_str(name, encoding=self.file_name_charset)

    def _decode_name(self, name):
        return force_text(name, encoding=self.file_name_charset)

    def _compress_content(self, content):
        """Gzip a given string content."""
        zbuf = BytesIO()
        zfile = GzipFile(mode='wb', compresslevel=6, fileobj=zbuf)
        try:
            zfile.write(content.read())
        finally:
            zfile.close()
        content.file = zbuf
        content.seek(0)
        return content

    def _open(self, name, mode='rb'):
        name = self._normalize_name(self._clean_name(name))
        f = S3BotoStorageFile(name, mode, self)
        if not f.s3object:
            raise IOError('File does not exist: %s' % name)
        return f

    def _save(self, name, content):
        cleaned_name = self._clean_name(name)
        name = self._normalize_name(cleaned_name)
        content_type = getattr(content, 'content_type',
            guess_content_type(name))
        kwargs = {}
        if self.encryption:
            # TODO: Make 'AES256' a setting
            kwargs['server_side_encryption'] = 'AES256'
        if self.gzip and content_type in self.gzip_content_types:
            content = self._compress_content(content)
            kwargs['content_encoding'] = 'gzip'

        content.name = cleaned_name
        encoded_name = self._encode_name(name)

        self.bucket.objects.create(
            key=encoded_name,
            body=content,
            acl=self.acl,
            content_type=content_type,
            storage_class=self.storage_class,
            **kwargs
        )

        if self.preload_metadata:
            self._entries[name] = self.get_s3object(name, use_cache=False)

        return cleaned_name

    def delete(self, name):
        name = self._normalize_name(self._clean_name(name))
        obj = self._construct_object(key=self._encode_name(name))
        obj.delete()

    def exists(self, name):
        name = self._normalize_name(self._clean_name(name))
        if self.entries:
            return name in self.entries
        return self.get_s3object(name) is not None

    def listdir(self, name):
        name = self._normalize_name(self._clean_name(name))
        # for the bucket.list and logic below name needs to end in /
        # But for the root path "" we leave it as an empty string
        if name:
            name += '/'

        dirlist = self.bucket.objects(prefix=self._encode_name(name))

        files = []
        dirs = set()
        base_parts = name.split("/")[:-1]
        for item in dirlist:
            parts = item.key.split("/")
            parts = parts[len(base_parts):]
            if len(parts) == 1:
                # File
                files.append(parts[0])
            elif len(parts) > 1:
                # Directory
                dirs.add(parts[0])
        return list(dirs), files

    def size(self, name):
        name = self._normalize_name(self._clean_name(name))
        return self.get_s3object(name).size

    def modified_time(self, name):
        try:
            from dateutil import parser, tz
        except ImportError:
            raise NotImplementedError()
        name = self._normalize_name(self._clean_name(name))
        entry = self.entries.get(name)
        # only call self.bucket.get_key() if the key is not found
        # in the preloaded metadata.
        if entry is None:
            entry = self.get_s3object(name)
        # convert to string to date
        last_modified_date = parser.parse(entry.last_modified)
        # if the date has no timzone, assume UTC
        if last_modified_date.tzinfo is None:
            last_modified_date = last_modified_date.replace(tzinfo=tz.tzutc())
        # convert date to local time w/o timezone
        timezone = tz.gettz(settings.TIME_ZONE)
        return last_modified_date.astimezone(timezone).replace(tzinfo=None)

    def url(self, name):
        name = self._normalize_name(self._clean_name(name))
        if self.custom_domain:
            return "%s//%s/%s" % (self.url_protocol,
                                  self.custom_domain, name)
        # TODO: Update to include other "calling" formats and signing
        return '{0}//{1}.s3.amazonaws.com/{2}'.format(
            self.url_protocol,
            self.bucket_name,
            name
        )

    def get_available_name(self, name):
        """ Overwrite existing file with the same name. """
        if FILE_OVERWRITE:
            name = self._clean_name(name)
            return name
        return super(S3BotoStorage, self).get_available_name(name)


class S3BotoStorageFile(File):
    """
    The default file object used by the S3BotoStorage backend.

    This file implements file streaming using boto's multipart
    uploading functionality. The file can be opened in read or
    write mode.

    This class extends Django's File class. However, the contained
    data is only the data contained in the current buffer. So you
    should not access the contained file object directly. You should
    access the data via this class.

    Warning: This file *must* be closed using the close() method in
    order to properly write the file to S3. Be sure to close the file
    in your application.
    """

    def __init__(self, name, mode, storage, buffer_size=FILE_BUFFER_SIZE):
        self._storage = storage
        self.name = name[len(self._storage.location):].lstrip('/')
        self._mode = mode
        self.s3object = storage.get_s3object(name)

        if not self.s3object and 'w' in mode:
            self.bucket.objects.create(
                key=storage._encode_name(name))
            self.s3object = storage.get_s3object(name)
        self._is_dirty = False
        self._file = None
        self._multipart_id = None
        # 5 MB is the minimum part size (if there is more than one part).
        # Amazon allows up to 10,000 parts.  The default supports uploads
        # up to roughly 50 GB.  Increase the part size to accommodate
        # for files larger than this.
        self._write_buffer_size = buffer_size
        self._write_counter = 0

    @property
    def size(self):
        return self.s3object.size

    def _get_file(self):
        if self._file is None:
            self._file = BytesIO()
            if 'r' in self._mode:
                self._is_dirty = False
                self.s3object.get()
                shutil.copyfileobj(self.s3object.body, self._file)
                self._file.seek(0)
            if self._storage.gzip and self.s3object.content_encoding == 'gzip':
                self._file = GzipFile(mode=self._mode, fileobj=self._file)

        return self._file

    def _set_file(self, value):
        self._file = value

    file = property(_get_file, _set_file)

    def read(self, *args, **kwargs):
        if 'r' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return super(S3BotoStorageFile, self).read(*args, **kwargs)

    def write(self, *args, **kwargs):
        if 'w' not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self._is_dirty = True
        if self._multipart_id is None:
            data = self.s3object.create_multipart_upload(
                acl=self._storage.acl,
                storage_class=self._storage.storage_class
            )
            # Keep track of the parts and the upload id
            self._multipart_upload = {'Parts': []}
            self._multipart_id = data['UploadId']
        if self._write_buffer_size <= self._buffer_file_size:
            self._flush_write_buffer()
        return super(S3BotoStorageFile, self).write(*args, **kwargs)

    @property
    def _buffer_file_size(self):
        pos = self.file.tell()
        self.file.seek(0, os.SEEK_END)
        length = self.file.tell()
        self.file.seek(pos)
        return length

    def _flush_write_buffer(self):
        """
        Flushes the write buffer.
        """
        if self._buffer_file_size:
            self._write_counter += 1
            self.file.seek(0)
            part = self.s3object.upload_part(
                upload_id=self._multipart_id,
                body=self.file,
                part_number=self._write_counter,
            )
            self._multipart_upload['Parts'].append({
                'PartNumber': self._write_counter,
                'ETag': part['ETag'],
            })
            self.file.close()
            self._file = None

    def close(self):
        if self._is_dirty:
            self._flush_write_buffer()
            self.s3object.complete_multipart_upload(
                upload_id=self._multipart_data['UploadId'],
                multipart_upload=self._multipart_upload
            )

        else:
            if not self._multipart_id is None:
                self.s3object.abort_multipart_upload(upload_id=self._multipart_id)
        self.s3object.close()
