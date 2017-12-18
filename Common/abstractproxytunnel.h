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
#include <botan/data_src.h>

namespace MyProxy {

	class Policy : public Botan::TLS::Policy {
		//std::vector<std::string> allowed_ciphers() const override {
		//	return {  "AES-256/GCM", "AES-128/GCM", "AES-256/CCM", "AES-128/CCM", "AES-256", "AES-128",
		//		"AES-256/CCM(8)", "AES-128/CCM(8)", "Camellia-256/GCM", "Camellia-128/GCM", "ARIA-256/GCM", "ARIA-128/GCM", "Camellia-256", "Camellia-128",
		//		"AES-128/OCB(12)", "AES-256/OCB(12)" };
		//}
		//std::vector<std::string> allowed_key_exchange_methods() const override {
		//	return { "CECPQ1", "ECDH", "DH","RSA", "SRP_SHA", "ECDHE_PSK", "DHE_PSK", "PSK" };
		//}
		bool require_cert_revocation_info() const override {
			return false;
		}
		bool allow_server_initiated_renegotiation() const override {
			return true;
		}
	};

	class Credentials : public Botan::Credentials_Manager
	{
	public:
		Credentials(std::string type, Botan::RandomNumberGenerator & rng):_rng(rng),_type(type){}
		//callback
		std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
			const std::string& type,
			const std::string& context) override
		{
			std::vector<Botan::Certificate_Store*> vec;
			if (type == _type) {
				std::shared_lock<std::shared_mutex> locker(_mutex);
				for (auto &store : _cas) {
					vec.push_back(store.get());
				}
			}
			return vec;
		}
		//callback
		std::vector<Botan::X509_Certificate> cert_chain(
			const std::vector<std::string>& algos,
			const std::string& type,
			const std::string& hostname) override
		{
			// return the certificate chain being sent to the tls client
			std::shared_lock<std::shared_mutex> locker(_mutex);
			for (auto const& i : _creds)
			{
				if (std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end())
					continue;
				if (hostname != "" && !i.certs[0].matches_dns_name(hostname))
					continue;
				return i.certs;
			}
			return std::vector<Botan::X509_Certificate>();
		}
		//callback
		Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
			const std::string& type,
			const std::string& context) override
		{
			// return the private key associated with the leaf certificate,
			std::shared_lock<std::shared_mutex> locker(_mutex);
			for (auto const& i : _creds)
			{
				if (cert == i.certs[0])
					return i.key.get();
			}
			return nullptr;
		}
		//add certificate and private key from file
		void addPair(const std::string& certPath, const std::string& keyPath) {
			std::unique_lock<std::shared_mutex> locker(_mutex);
			Certificate_Info cert;
			cert.key.reset(Botan::PKCS8::load_key(keyPath, _rng));
			Botan::DataSource_Stream in(certPath);
			while (!in.end_of_data()) {
				try
				{
					cert.certs.push_back(Botan::X509_Certificate(in));
				}
				catch (std::exception&)
				{
				}
				_creds.push_back(cert);
			}
		}
		//add cacert from file
		void addCA(const std::string& path) {
			std::unique_lock<std::shared_mutex> locker(_mutex);
			auto store = std::make_shared<Botan::Certificate_Store_In_Memory>();
			Botan::DataSource_Stream in(path);
			while (!in.end_of_data()) {
				try {
					store->add_certificate(std::make_shared<Botan::X509_Certificate>(in));
				}
				catch (std::exception&) {

				}
			}
			_cas.push_back(store);
		}
	private:
		struct Certificate_Info
		{
			std::vector<Botan::X509_Certificate> certs;
			std::shared_ptr<Botan::Private_Key> key;
		};
		std::vector<Certificate_Info> _creds;
		std::vector<std::shared_ptr<Botan::Certificate_Store>> _cas;
		std::shared_mutex _mutex; //need?
		Botan::RandomNumberGenerator & _rng;
		std::string _type;
	};

	class TLSContext {
	public:
		std::unique_ptr<Botan::RandomNumberGenerator> rng;
		std::unique_ptr<Botan::TLS::Session_Manager> session_mgr;
		std::unique_ptr<Credentials> creds;
		std::unique_ptr<Botan::TLS::Policy> policy;
		TLSContext(std::unique_ptr<Botan::RandomNumberGenerator> &&_rng,
			std::unique_ptr<Botan::TLS::Session_Manager> && _session_mgr,
			std::unique_ptr<Credentials> && _creds,
			std::unique_ptr<Botan::TLS::Policy> && _policy) :
			rng(std::move(_rng)), session_mgr(std::move(_session_mgr)), creds(std::move(_creds)), policy(std::move(_policy)) {}
	};

	class AbstractProxyTunnel : public BasicProxyTunnel, public Botan::TLS::Callbacks {
	public:
		//channel: Client or Server, io: io_service
		AbstractProxyTunnel(boost::asio::io_service &io, std::string loggerName = "AbstractProxyTunnel") :
			BasicProxyTunnel(io, loggerName),_writeStrand(io){}
		virtual void write(std::shared_ptr<DataVec> dataPtr) override;
		virtual void tls_emit_data(const uint8_t data[], size_t size) override;
		virtual void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override;
		virtual void tls_alert(Botan::TLS::Alert alert) override;
		//If this function wishes to cancel the handshake, it can throw an exception
		//which will send a close message to the counterparty and reset the connection state.
		virtual bool tls_session_established(const Botan::TLS::Session& session) override;
	protected:
		//cache data to _readBuffer2 and call handleRead when a packet is received completely.
		virtual void onReceived(const boost::system::error_code & ec, size_t bytes, std::shared_ptr<BasicProxyTunnel> self) override;
		//called when a packet is received completely.
		virtual void handleRead(std::shared_ptr<DataVec> data) override = 0;
		std::shared_ptr<Botan::TLS::Channel>& channel() {
			return _channel;
		}
	private:
		//decrypted data buffer
		boost::asio::streambuf _readBuffer2;
		//channel write strand, different to socket write strand.
		boost::asio::strand _writeStrand;
		//protect channel state
		std::shared_mutex _stateMutex;
		//abstract channel
		std::shared_ptr<Botan::TLS::Channel> _channel;
	};
}