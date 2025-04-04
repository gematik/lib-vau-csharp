FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:35792ea4ad1db051981f62b313f1be3b46b1f45cadbaa3c288cd0d3056eefb83
WORKDIR /VauProxyClientCSharp

COPY /Docker/VauProxyClientCSharp/bin/Release/net8.0/publish ./


ENTRYPOINT ["dotnet", "VauProxyClientCSharp.dll"]