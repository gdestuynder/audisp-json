VERSION=$(make version)
echo Building and releasing $VERSION in 5 seconds...
sleep 5

mkdir release
docker run --rm -ti -v $(pwd):/build amazonlinux /bin/bash -c "yum install -y make && cd /build && make rpm-deps" && \
  mv audisp-json-${VERSION}-1.x86_64.rpm release/audisp-json-${VERSION}-1.x86_64-amazon.rpm
sudo make clean || exit

docker run --rm -ti -v $(pwd):/build centos:7 /bin/bash -c "yum install -y make && cd /build && make rpm-deps" && \
  mv audisp-json-${VERSION}-1.x86_64.rpm release/audisp-json-${VERSION}-1.x86_64-centos7.rpm
sudo make clean || exit

docker run --rm -ti -v $(pwd):/build ubuntu:14.04 /bin/bash -c "apt-get update && apt-get install -y make && cd /build && make deb-deps" && \
  mv audisp-json_${VERSION}_amd64.deb release/audisp-json-${VERSION}-1.x86_64-ubuntu1404.deb
sudo make clean || exit

hub release create -m "Releasing ${VERSION}" ${VERSION}
hub release edit -m "Releasing ${VERSION}" -a release/audisp-json-${VERSION}-1.x86_64-centos7.rpm ${VERSION}
hub release edit -m "Releasing ${VERSION}" -a release/audisp-json-${VERSION}-1.x86_64-amazon.rpm ${VERSION}
hub release edit -m "Releasing ${VERSION}" -a release/audisp-json-${VERSION}-1.x86_64-ubuntu1404.deb ${VERSION}
