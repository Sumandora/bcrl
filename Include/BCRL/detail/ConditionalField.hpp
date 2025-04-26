#ifndef BCRL_DETAIL_CONDITIONALFIELD_HPP
#define BCRL_DETAIL_CONDITIONALFIELD_HPP

#include <type_traits>
#include <variant>

namespace BCRL::detail {
	template <bool Cond, typename T>
	using ConditionalField = std::conditional_t<Cond, T, std::monostate>;

	template <typename T>
	auto conditional_init(auto... pack)
	{
		if constexpr (std::is_same_v<T, std::monostate>)
			return std::monostate{};
		else
			return T(pack...);
	}
}

#endif
