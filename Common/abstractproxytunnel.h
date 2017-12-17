#pragma once
#include "basic.h"
//botan
#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/certstor.h>
#include <botan/x509_ca.h>
#include <botan/credentials_manager.h>

namespace MyProxy {

	class Credentials : public Botan::Credentials_Manager
	{
	public:
		Credentials(Botan::RandomNumberGenerator & rng):_rng(rng) {}
		//callback
		std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
			const std::string& type,
			const std::string& context) override
		{
			// if client authentication is required, this function
			// shall return a list of certificates of CAs we trust
			// for tls client certificates, otherwise return an empty list
			//return std::vector<Botan::Certificate_Store*>();
			return { new Botan::Certificate_Store_In_Memory(cas()) };
		}
		//callback
		std::vector<Botan::X509_Certificate> cert_chain(
			const std::vector<std::string>& cert_key_types,
			const std::string& type,
			const std::string& context) override
		{
			// return the certificate chain being sent to the tls client
			return certs();
		}
		//callback
		Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
			const std::string& type,
			const std::string& context) override
		{
			// return the private key associated with the leaf certificate,
			return getKey(cert);
		}
		//add certificate and private key from memory
		void addPair(const Botan::X509_Certificate& cert, std::shared_ptr<Botan::Private_Key> key) {
			std::unique_lock<std::shared_mutex> locker(_mutex);
			pairs[cert] = key;
			_certs.insert(cert);
		}
		//add certificate and private key from file
		void addPair(const std::string& certPath, const std::string& keyPath) {
			std::unique_lock<std::shared_mutex> locker(_mutex);
			Botan::X509_Certificate cert(certPath);
			std::shared_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(keyPath,_rng));
			_certs.insert(cert);
			pairs.insert_or_assign(std::move(cert), key);
		}
		//get cert chain
		std::vector<Botan::X509_Certificate> certs() {
			std::shared_lock<std::shared_mutex> locker(_mutex);
			return { _certs.begin(), _certs.end() };
		}
		//memory safe?
		Botan::Private_Key* getKey(const Botan::X509_Certificate& cert) {
			std::shared_lock<std::shared_mutex> locker(_mutex);
			return pairs[cert].get();
		}
		void addCA(const std::string& path) {
			std::unique_lock<std::shared_mutex> locker(_mutex);
			_caStore.add_certificate(Botan::X509_Certificate(path));
		}
		Botan::Certificate_Store_In_Memory cas() {
			std::shared_lock<std::shared_mutex> locker(_mutex);
			return _caStore;
		}
	private:
		Botan::Certificate_Store_In_Memory _caStore;
		std::map<Botan::X509_Certificate, std::shared_ptr<Botan::Private_Key>> pairs;
		std::set<Botan::X509_Certificate> _certs;
		std::shared_mutex _mutex;
		Botan::RandomNumberGenerator & _rng;
	};

	class AbstractProxyTunnel : public BasicProxyTunnel, public Botan::TLS::Callbacks {
	public:
		//channel: Client or Server, io: io_service
		AbstractProxyTunnel(std::shared_ptr<Botan::TLS::Channel> channel, boost::asio::io_service &io, std::string loggerName = "AbstractProxyTunnel") :
			BasicProxyTunnel(io, loggerName),_channel(channel),_readStrand(io){}
		virtual void write(std::shared_ptr<DataVec> dataPtr) override;
	protected:
		virtual void onReceived(const boost::system::error_code & ec, size_t bytes, std::shared_ptr<BasicProxyTunnel> self) override;
		virtual void handleRead(std::shared_ptr<DataVec> data) override = 0;
		virtual void tls_emit_data(const uint8_t data[], size_t size) override;
		virtual void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override;
		virtual void tls_alert(Botan::TLS::Alert alert) override;
		//If this function wishes to cancel the handshake, it can throw an exception
		//which will send a close message to the counterparty and reset the connection state.
		virtual bool tls_session_established(const Botan::TLS::Session& session) override;
	private:
		boost::asio::streambuf _readBuffer2;
		boost::asio::strand _readStrand;
		std::shared_ptr<Botan::TLS::Channel> _channel;
	};

	inline void AbstractProxyTunnel::write(std::shared_ptr<DataVec> dataPtr)
	{
		_channel->send(reinterpret_cast<unsigned char*>(dataPtr->data()),dataPtr->size());
	}

	inline void AbstractProxyTunnel::onReceived(const boost::system::error_code & ec, size_t bytes, std::shared_ptr<BasicProxyTunnel> self)
	{
		if (ec) {
			logger()->error("AbstractProxyTunnel::onReceived() error: {}", ec.message());
			_channel->close();
			disconnect();
			return;
		}
		_channel->received_data(boost::asio::buffer_cast<const unsigned char*>(readbuf().data()), bytes);
		readbuf().consume(bytes);
		nextRead();
	}
}