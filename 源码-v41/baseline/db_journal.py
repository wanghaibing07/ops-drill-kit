"""Conservative classification of an interrupted isolated import batch.

The caller must independently verify the current run and MySQL instance and
derive both expected hashes from the validated, ordered source data.  This
module does not connect to MySQL, persist state, or perform a retry.
"""
import re

_SHA = re.compile(r'[0-9a-f]{64}\Z')


def reconcile(*, instance_verified, start, end, actual_count, actual_sha,
              expected_before_sha, expected_after_sha):
    """Return an observation, never execute or authorize a database change."""
    if instance_verified is not True:
        return 'IDENTITY_UNVERIFIED'
    if (type(start) is not int or type(end) is not int or type(actual_count) is not int
            or not 1 <= start <= end <= 500000 or not 0 <= actual_count <= 500000
            or any(not isinstance(x,str) or not _SHA.fullmatch(x)
                   for x in (actual_sha,expected_before_sha,expected_after_sha))):
        return 'NEEDS_INSPECTION'
    if actual_count == start-1 and actual_sha == expected_before_sha:
        return 'MATCHES_BEFORE_BATCH'
    if actual_count == end and actual_sha == expected_after_sha:
        return 'MATCHES_AFTER_BATCH'
    return 'NEEDS_INSPECTION'
