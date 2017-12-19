#include "abstractproxytunnel.h"
#include <botan/tls_client.h>

using namespace boost::asio;

namespace MyProxy {
	
	/*
		BasicProxyTunnel::Callbacks implement
	*/

	void AbstractProxyTunnel::tls_emit_data(const uint8_t data[], size_t size)
	{
		write_ex(std::make_shared<DataVec>(DataVec{ data, data + size }));
	}
	void AbstractProxyTunnel::tls_record_received(uint64_t /*seq_no*/, const uint8_t data[], size_t size)
	{
		IoHelper io(&_readBuffer2);
		io.write(reinterpret_cast<const char*>(data), size);
		auto rawData = buffer_cast<const char*>(_readBuffer2.data());
		if (Package::remainBytes(rawData, _readBuffer2.size()) > 0)
			return;
		else {
			auto pkgSz = Package::getSize(rawData);
			auto pkgData = std::make_shared<DataVec>(pkgSz);
			io.read(*pkgData, pkgSz);
			//_readBuffer2.consume(pkgSz);
			handleRead(pkgData);
		}
	}
	void AbstractProxyTunnel::tls_alert(Botan::TLS::Alert alert)
	{
		auto vec = alert.serialize();
		logger()->error("Alert: {}:{}", alert.type_string(),std::string{ vec.begin(), vec.end() });
	}
	bool AbstractProxyTunnel::tls_session_established(const Botan::TLS::Session & session)
	{
		return false;
	}
	void AbstractProxyTunnel::write(std::shared_ptr<DataVec> dataPtr)
	{
		_writeStrand.post([this, dataPtr, self = shared_from_this()]{
			try {
				std::shared_lock<std::shared_mutex> locker(_stateMutex);
				if (_channel->is_active())
					_channel->send(reinterpret_cast<const uint8_t*>(dataPtr->data()), dataPtr->size());
			}
			catch (const std::exception &ex) {
				logger()->error("_channel->send() error: {}", ex.what());
				std::unique_lock<std::shared_mutex> locker(_stateMutex);
				_channel->close();
				locker.unlock();
				disconnect();
			}
		});
	}
	void AbstractProxyTunnel::onReceived(const boost::system::error_code & ec, size_t bytes, std::shared_ptr<BasicProxyTunnel> self)
	{
		if (ec) {
			logger()->error("AbstractProxyTunnel::onReceived() error: {}", ec.message());
			std::unique_lock<std::shared_mutex> locker(_stateMutex);
			if (!_channel->is_closed())
				_channel->close();
			locker.unlock();
			disconnect();
			return;
		}
		try {
			std::shared_lock<std::shared_mutex> locker(_stateMutex);
			if (!_channel->is_closed())
				_channel->received_data(boost::asio::buffer_cast<const uint8_t*>(readbuf().data()), bytes);
		}
		catch (const std::exception &ex) {
			logger()->error("_channel->received_data() error: {}", ex.what());
			std::unique_lock<std::shared_mutex> locker(_stateMutex);
			_channel->close();
			locker.unlock();
			disconnect();
		}
		readbuf().consume(bytes);
		nextRead();
	}
}