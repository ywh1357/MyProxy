#include "abstractproxytunnel.h"
#include <botan/tls_client.h>

using namespace boost::asio;

namespace MyProxy {
	
	/*
		BasicProxyTunnel::Callbacks implement
	*/

	void AbstractProxyTunnel::tls_emit_data(const uint8_t data[], size_t size)
	{
		// send data to tls server, e.g., using BSD sockets or boost asio
		this->write_ex(std::make_shared<DataVec>(DataVec{ data, data + size }));
	}
	void AbstractProxyTunnel::tls_record_received(uint64_t /*seq_no*/, const uint8_t data[], size_t size)
	{
		// process full TLS record received by tls server, e.g.,
		// by passing it to the application
		IoHelper io(&_readBuffer2);
		io.write(reinterpret_cast<const char*>(data), size);
		auto rawData = buffer_cast<const char*>(_readBuffer2.data());
		if (Package::remainBytes(rawData, _readBuffer2.size()) > 0)
			return;
		else {
			auto pkgSz = Package::getSize(rawData);
			auto pkgData = std::make_shared<DataVec>(pkgSz);
			io.read(*pkgData, pkgSz);
			_readBuffer2.consume(pkgSz);
			this->handleRead(pkgData);
		}
	}
	void AbstractProxyTunnel::tls_alert(Botan::TLS::Alert alert)
	{
		// handle a tls alert received from the tls server
		auto vec = alert.serialize();
		logger()->error("Alert: {}:{}", alert.type_string(),std::string{ vec.begin(), vec.end() });
	}
	bool AbstractProxyTunnel::tls_session_established(const Botan::TLS::Session & session)
	{
		// the session with the tls server was established
		// return false to prevent the session from being cached, true to
		// cache the session in the configured session manager
		return true;
	}
}