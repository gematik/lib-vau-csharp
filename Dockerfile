FROM mcr.microsoft.com/dotnet/sdk:8.0

RUN /usr/sbin/useradd libvau
USER libvau

WORKDIR /VauProxyClientCSharp

COPY /Docker/VauProxyClientCSharp/bin/Release/net80/publish ./


ENTRYPOINT ["dotnet", "VauProxyClientCSharp.dll"]