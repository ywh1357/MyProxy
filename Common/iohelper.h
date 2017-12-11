#pragma once
#ifndef MYPROXY_IOHELPER
#define MYPROXY_IOHELPER

#include <iostream>
#include <vector>
#include <memory>
#include <tuple>
#include <boost/endian/conversion.hpp>

namespace MyProxy {

	//enum Tesst: uint8_t{ first, last };

	using DataVec = std::vector<char>;

	template <typename T>
	T hostToNetwork(T value) {
		return static_cast<T>(boost::endian::native_to_big(value));
	}

	template<typename T>
	T networkToHost(T value) {
		return static_cast<T>(boost::endian::big_to_native(value));
	}

	template <typename T>
	struct TnS {
		typedef T type;
		const size_t size;
		constexpr TnS(size_t size = sizeof(T)) :size(size) {}
	};

	constexpr TnS<uint8_t> _1B;
	constexpr TnS<uint16_t> _2B;
	constexpr TnS<uint32_t> _4B;
	constexpr TnS<uint64_t> _8B;
	using _datavec = TnS<DataVec>;

	template <typename TupleType, typename Func, size_t ...I>
	void for_each(TupleType& tuple, Func f, std::index_sequence<I...>) {
		std::initializer_list<int>{
			(f(std::get<I>(tuple)), 0)...
		};
	}

	class DataVecBuf : public std::streambuf {
		using Base = std::streambuf;
	public:
		DataVecBuf(DataVec &vec);
	protected:
		int_type overflow(int_type ch) override;
		int_type underflow() override;
		int_type uflow() override;
		std::streamsize showmanyc() override;
		std::streamsize xsputn(const char* s, std::streamsize count) override;
		std::streamsize xsgetn(char* s, std::streamsize count) override;
		//pos_type seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
		//pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
	private:
		std::vector<char> &vec;
		char* _last;
		char* _first;
		std::streamsize _gpos = 0;
	};

	class IoHelper {
		template <typename ...Args>
		friend IoHelper& operator<<(IoHelper &os, const std::tuple<Args...>& value);
		template <typename T>
		friend IoHelper& operator<<(IoHelper &os, const T& tuple);
		template <typename ...Args>
		friend IoHelper& operator>>(IoHelper &is, std::tuple<Args...>& tuple);
		template <typename T>
		friend IoHelper& operator>>(IoHelper &is, T& value);
	public:
		IoHelper(std::streambuf *buf, bool _convert = false) :ios(buf), convert(_convert) {}
		IoHelper(DataVec &vec, bool _convert = false) :ios(makeBuffer(vec)), convert(_convert) {}

		template <typename T>
		void write(const T& value, size_t bytes = sizeof(T));

		template <typename T>
		void read(T& value, size_t bytes = sizeof(T));

		template <typename T>
		T getValue(size_t count = sizeof(T));

		template <typename ...Args>
		void getValues(Args& ...args);

		template <typename ...Types, typename ...Args>
		void getCastedValues(Args& ...args);

		template <typename ...OutputTypes, typename ...TnSs>
		std::tuple<OutputTypes...> getTuple(TnSs ...tnss) {
			return std::tuple<OutputTypes...>{ static_cast<OutputTypes>(getSomeValue(tnss))... };
		}

		template <typename ...Args>
		void putValues(const Args& ...args);

		template <typename ...Types, typename ...Args>
		void putCastedValues(const Args& ...args);

	private:
		template <typename S, typename D>
		typename std::enable_if<!std::is_same<S, D>::value, void>::type
			getSomeValue(D& value) {
			S temp;
			read(temp);
			value = static_cast<D>(temp);
		}
		template <typename S, typename D>
		typename std::enable_if<std::is_same<S, D>::value, void>::type
			getSomeValue(D& value) {
			read(value);
		}
		template <typename T>
		static T parseType(size_t size) {
			return T();
		}
		template <typename T>
		typename TnS<T>::type getSomeValue(TnS<T> tns) {
			typename TnS<T>::type value = parseType<typename TnS<T>::type>(tns.size);
			read(value);
			return value;
		}
		DataVecBuf* makeBuffer(DataVec &vec) {
			m_buf = std::make_shared<DataVecBuf>(vec);
			return m_buf.get();
		}
		std::shared_ptr<DataVecBuf> m_buf;
		std::iostream ios;
		bool convert;
	};

	template<typename T>
	inline void IoHelper::write(const T & value, size_t bytes)
	{
		if (convert && std::is_integral<T>::value) {
			T temp = value;
			temp = boost::endian::native_to_big(temp);
			ios.write(reinterpret_cast<const char*>(&temp), sizeof(T));
		}
		else {
			ios.write(reinterpret_cast<const char*>(&value), sizeof(T));
		}
	}

	template<typename T>
	inline void IoHelper::read(T & value, size_t bytes)
	{
		ios.read(reinterpret_cast<char*>(&value), bytes);
		if (convert && std::is_integral<T>::value) {
			boost::endian::big_to_native_inplace(value);
		}
	}

	template<typename T>
	inline T IoHelper::getValue(size_t count)
	{
		T value;
		read(value);
		return value;
	}

	template<typename ...Args>
	inline void IoHelper::getValues(Args & ...args)
	{
		std::initializer_list<int>{
			(read(args), 0)...
		};
	}

	template<typename ...Types, typename ...Args>
	inline void IoHelper::getCastedValues(Args & ...args)
	{
		std::initializer_list<int>{
			(getSomeValue<Types>(args), 0)...
		};
	}

	template<typename ...Args>
	inline void IoHelper::putValues(const Args & ...args)
	{
		std::initializer_list<int>{
			(write(args), 0)...
		};
	}

	template<typename ...Types, typename ...Args>
	inline void IoHelper::putCastedValues(const Args & ...args)
	{
		std::initializer_list<int>{
			(write(static_cast<Types>(args)), 0)...
		};
	}

	template <>
	DataVec IoHelper::parseType<DataVec>(size_t size);
	template<>
	void IoHelper::write<std::vector<char>>(const std::vector<char> & value, size_t);
	template<>
	void IoHelper::read<std::vector<char>>(std::vector<char> & value, size_t bytes);
	template <>
	std::vector<char> IoHelper::getValue<std::vector<char>>(size_t count);

	template<typename ...Args>
	IoHelper & operator<<(IoHelper & os, const std::tuple<Args...>& tuple)
	{
		for_each(tuple, [&os](const auto& v) {
			os.write(v);
		}, std::make_index_sequence<sizeof...(Args)>());
		return os;
	}
	template<typename T>
	IoHelper & operator<<(IoHelper & os, const T & value)
	{
		os.write(value);
		return os;
	}
	template<typename ...Args>
	IoHelper & operator>>(IoHelper & is, std::tuple<Args...>& tuple)
	{
		for_each(tuple, [&is](auto& v) {
			is.read(v);
		}, std::make_index_sequence<sizeof...(Args)>());
		return is;
	}
	template<typename T>
	IoHelper & operator>>(IoHelper & is, T & value)
	{
		is.read(value);
		return is;
	}
}

#endif // MYPROXYIOHELPER
