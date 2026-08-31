# Longfellow ZK 1.x ABI policy

The shared library SONAME is `liblongfellow-zk.so.1`. Compatible 1.x releases
retain SONAME 1; a future incompatible ABI requires a new major release and
SONAME. Only declarations marked
`LONGFELLOW_ZK_API` are supported dynamic-link entry points.  Header-only
templates and inline gadgets remain compiled by the consumer.

Callers own memory that they allocate and must not transfer STL containers or
allocator-owned objects across this ABI.  The library is built without an ABI
guarantee across different compiler or C++ standard-library versions.  Its
public operations do not throw as part of their contract; builds that disable
exceptions and RTTI remain supported, including the existing WASI workflow.
Thread safety is operation-specific: callers must synchronize shared mutable
objects, while independent calls that use caller-owned state are safe.
