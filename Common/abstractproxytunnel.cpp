#include "abstractproxytunnel.h"
#include <botan/tls_client.h>

using namespace boost::asio;

namespace MyProxy {
	AbstractProxyTunnel::~AbstractProxyTunnel()
	{
		boost::system::error_code ec;
		connection().close(ec);
		if (ec) {
			logger()->error("close error: {}", ec.message());
		}
	}
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
		_strand.post([this, dataPtr, self = shared_from_this()]{
			if (_state.load() & RunningState::shutdown_write)
				return;
			try {
				if (_channel->is_active())
					_channel->send(reinterpret_cast<const uint8_t*>(dataPtr->data()), dataPtr->size());
			}
			catch (const std::exception &ex) {
				logger()->error("_channel->send() error: {}", ex.what());
				shutdown();
			}
		});
	}
	void AbstractProxyTunnel::write_ex(std::shared_ptr<DataVec> dataPtr)
	{
		if (_state.load() & RunningState::shutdown_write)
			return;
		_strand.post([this, dataPtr = std::move(dataPtr), self = shared_from_this()]{
			_writeQueue.push(std::move(dataPtr));
			if (_writeQueue.size() > 1) {
				return;
			}
			else {
				write_impl();
			}
		});
	}
	void AbstractProxyTunnel::write_impl()
	{
		async_write(connection(), boost::asio::buffer(*_writeQueue.front()), boost::asio::transfer_all(),
			_strand.wrap([this, self = shared_from_this()](const boost::system::error_code &ec, size_t) {
			_writeQueue.pop(); //drop
			if (ec) {
				if (_state.load() & RunningState::shutdown_write)
					return;
				logger()->error("write error: ", ec.message());
				shutdown();
				disconnect();
				return;
			}
			if (!_writeQueue.empty()) {
				write_impl();
			}
			else if (_state.load() & RunningState::shutdown_write) {
				boost::system::error_code shutdown_ec;
				connection().shutdown(connection().shutdown_send, shutdown_ec);
				if (shutdown_ec)
					logger()->debug("shutdown send error: ", shutdown_ec.message());
				//disconnect();
			}
		}));
	}
	void AbstractProxyTunnel::nextRead()
	{
		using namespace boost::asio;
		connection().async_read_some(_readBuffer.prepare(8 * 1024),
			_strand.wrap([this, self = shared_from_this()](const boost::system::error_code ec, size_t bytes){
			if (ec) {
				if (_state.load() & RunningState::shutdown_read)
					return;
				shutdown();
			}
			try {
				std::shared_lock<std::shared_mutex> locker(_stateMutex);
				if (!_channel->is_closed())
					_channel->received_data(boost::asio::buffer_cast<const uint8_t*>(_readBuffer.data()), bytes);
			}
			catch (const std::exception &ex) {
				logger()->error("_channel->received_data() error: {}", ex.what());
				shutdown();
				return;
			}
			_readBuffer.consume(bytes);
			nextRead();
			})
		);
	}
	void AbstractProxyTunnel::disconnect()
	{
		if (!_running.exchange(false))
			return;
		manager().clear();
		if (onDisconnected)
			onDisconnected();
	}
	void AbstractProxyTunnel::shutdown(RunningState state = RunningState::shutdown_both)
	{
		using shutdown_type = boost::asio::socket_base::shutdown_type;
		auto op = state & ~RunningState(std::atomic_fetch_or(&_state, state));
		if (op & RunningState::shutdown_read) {
			_strand.post([this, self = shared_from_this()]{
				connection().shutdown(shutdown_type::shutdown_receive);
				});
		}
		//if (op & RunningState::shutdown_write) {
		//	_strand.post([this, self = shared_from_this()]{
		//		_connection.shutdown(shutdown_type::shutdown_send);
		//	});
		//}
	}

}