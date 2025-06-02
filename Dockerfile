FROM centos:7

# Set up repos and install packages
RUN sed -i 's|mirrorlist.centos.org|vault.centos.org|g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-Base.repo && \
    yum clean all && \
    yum groupinstall -y "Development Tools" && \
    yum install -y fuse fuse-devel openssl-devel pkgconfig && \
    yum clean all

# Work directory for code
WORKDIR /usr/src/app

# Copy all necessary source files
COPY *.c *.h Makefile ./

# Build the FUSE filesystem
RUN make

# Default command: interactive shell
CMD ["/bin/bash"]
