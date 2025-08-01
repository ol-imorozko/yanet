#include <arpa/inet.h>
#include <netdb.h>

#include <array>
#include <list>
#include <map>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef ACL_DEBUG
#define ACL_DEBUGLEVEL (1)
#else
#define ACL_DEBUGLEVEL (0)
#endif

#define ACL_DBGMSG(msg)                                                             \
	if (ACL_DEBUGLEVEL)                                                         \
	{                                                                           \
		std::cerr << "ACL_DEBUG: " << __func__ << ": " << msg << std::endl; \
	}

#include "acl.h"
#include "acl/dict.h"
#include "acl/rule.h"
#include "acl_compiler.h"

namespace acl
{

struct dispatcher_rules_t
{
	std::list<rule_t> rules;

	dispatcher_rules_t(const controlplane::base::acl_t& acl)
	{
		ref_t<filter_id_t> dir_in = new filter_id_t(0);

		for (const auto& item : acl.nextModuleRules)
		{
			if (!item.flow)
			{
				continue;
			}

			ref_t<filter_network_t> src;
			ref_t<filter_network_t> dst;
			ref_t<filter_prm8_t> flags;
			ref_t<filter_proto_t> proto;

			if (item.network)
			{
				const auto& network = *item.network;

				auto* _src = new filter_network_t;
				auto* _dst = new filter_network_t;

				if (std::holds_alternative<controlplane::base::acl_rule_network_ipv4_t>(network))
				{
					const auto& ipv4 = std::get<controlplane::base::acl_rule_network_ipv4_t>(network);

					for (const auto& pref : ipv4.sourcePrefixes)
					{
						_src->networks.emplace_back(pref);
					}
					for (const auto& pref : ipv4.destinationPrefixes)
					{
						_dst->networks.emplace_back(pref);
					}
				}
				else if (std::holds_alternative<controlplane::base::acl_rule_network_ipv6_t>(network))
				{
					const auto& ipv6 = std::get<controlplane::base::acl_rule_network_ipv6_t>(network);

					for (const auto& pref : ipv6.sourcePrefixes)
					{
						_src->networks.emplace_back(pref);
					}
					for (const auto& pref : ipv6.destinationPrefixes)
					{
						_dst->networks.emplace_back(pref);
					}
				}
				else
				{
					throw std::runtime_error("internal error");
				}

				src = _src;
				dst = _dst;
			}

			if (item.fragment)
			{
				flags = new filter_prm8_t(*item.fragment, true);
			}

			// XXX: should we add some checks that we don't generate
			//      transport layer filters for fragments?
			if (item.transport)
			{
				const auto& transport = *item.transport;

				if (std::holds_alternative<controlplane::base::acl_rule_transport_tcp_t>(transport))
				{
					const auto& tcp = std::get<controlplane::base::acl_rule_transport_tcp_t>(transport);

					ref_t<filter_prm8_t> flags;

					if (tcp.flags)
					{
						const auto& [set_mask, clear_mask] = tcp.flags.value();
						flags = tcpflags(set_mask, clear_mask);
					}

					proto = new filter_proto_t(new filter_prm8_t(IPPROTO_TCP),
					                           new filter_prm16_t(tcp.sourcePorts),
					                           new filter_prm16_t(tcp.destinationPorts),
					                           flags);
				}
				else if (std::holds_alternative<controlplane::base::acl_rule_transport_udp_t>(transport))
				{
					const auto& udp = std::get<controlplane::base::acl_rule_transport_udp_t>(transport);
					proto = new filter_proto_t(new filter_prm8_t(IPPROTO_UDP),
					                           new filter_prm16_t(udp.sourcePorts),
					                           new filter_prm16_t(udp.destinationPorts),
					                           nullptr);
				}
				else if (std::holds_alternative<controlplane::base::acl_rule_transport_icmpv4_t>(transport))
				{
					const auto& icmpv4 = std::get<controlplane::base::acl_rule_transport_icmpv4_t>(transport);

					proto = new filter_proto_t(new filter_prm8_t(IPPROTO_ICMP),
					                           icmp_prm1(icmpv4.types, icmpv4.codes),
					                           new filter_prm16_t(icmpv4.identifiers),
					                           nullptr);
				}
				else if (std::holds_alternative<controlplane::base::acl_rule_transport_icmpv6_t>(transport))
				{
					const auto& icmpv6 = std::get<controlplane::base::acl_rule_transport_icmpv6_t>(transport);

					proto = new filter_proto_t(new filter_prm8_t(IPPROTO_ICMPV6),
					                           icmp_prm1(icmpv6.types, icmpv6.codes),
					                           new filter_prm16_t(icmpv6.identifiers),
					                           nullptr);
				}
				else if (std::holds_alternative<controlplane::base::acl_rule_transport_other_t>(transport))
				{
					const auto& other = std::get<controlplane::base::acl_rule_transport_other_t>(transport);
					proto = new filter_proto_t(new filter_prm8_t(other.protocolTypes), nullptr, nullptr, nullptr);
				}
			}

			rules.emplace_back(new filter_t(nullptr, src, dst, flags, proto, dir_in, nullptr), *item.flow, ids_t(), false);
		}

		{
			// drop all input packets by default
			// this rule is needed for correct determination of single from networks
			common::globalBase::tFlow flow;
			flow.type = common::globalBase::eFlowType::drop;
			rules.emplace_back(new filter_t(nullptr, nullptr, nullptr, nullptr, nullptr, dir_in, nullptr), flow, ids_t(), false);
		}
		{
			// allow all output packets by default
			ref_t<filter_id_t> dir_out = new filter_id_t(1);
			common::globalBase::tFlow flow;
			flow.type = common::globalBase::eFlowType::logicalPort_egress;
			rules.emplace_back(new filter_t(nullptr, nullptr, nullptr, nullptr, nullptr, dir_out, nullptr), flow, ids_t(), false);
		}
	}
};

struct firewall_rules_t
{
	std::map<unsigned int, std::vector<rule_t>> rules;

	firewall_rules_t(const controlplane::base::acl_t& acl, uint32_t& auto_id)
	{
		auto& configp = acl.firewall;
		for (auto& [ruleno, ipfw_rules] : configp->m_rules)
		{
			auto& yanet_rules = rules[ruleno];
			for (auto rulep : ipfw_rules)
			{
				// skip and log rules that have failed validation
				switch (rulep->vstatus)
				{
					case ipfw::rule_t::validation_status_t::UNKNOWN:
						break;
					default:
						YANET_LOG_WARNING("%s: rule %u: %s: has failed validation: %s\n",
						                  __func__,
						                  rulep->ruleno,
						                  configp->format_location(rulep->location).data(),
						                  rulep->vstatus_to_string().data());
						continue;
				}
				// handle only supported actions
				switch (rulep->action)
				{
					case ipfw::rule_action_t::SKIPTO:
						// expand tablearg rules
						if (std::holds_alternative<int64_t>(rulep->action_arg) &&
						    std::get<int64_t>(rulep->action_arg) == 0)
						{
							// skipto tablearg from table(X) to any
							// skipto tablearg from any to table(X)
							if (rulep->src_targ || rulep->dst_targ)
							{
								const auto& table = std::get<ipfw::tables::table_type_t>(
								        configp->m_tables[rulep->targ_name]);
								const auto& prefixes = std::get<ipfw::tables::prefix_skipto_t>(table);
								// create single rule_t(filter, ruleno, skipto) for each prefix
								for (const auto& [prefix, label] : prefixes)
								{
									if (label.empty())
									{
										YANET_LOG_WARNING("%s: rule %u: expanding error: empty label for prefix %s\n",
										                  __func__,
										                  rulep->ruleno,
										                  prefix.toString().data());
										continue;
									}
									// resolve label into ruleno
									const auto& search = configp->m_labels.find(label);
									if (search == configp->m_labels.end())
									{
										YANET_LOG_WARNING("%s: rule %u: expanding error: label %s not found\n",
										                  __func__,
										                  rulep->ruleno,
										                  label.data());
										continue;
									}
									auto skipto = std::get<unsigned int>(search->second);
									// backwards skipto is not allowed
									if (skipto <= rulep->ruleno)
									{
										YANET_LOG_WARNING("%s: rule %u: attempt to jump backwards: %s -> %s (%u)\n",
										                  __func__,
										                  rulep->ruleno,
										                  prefix.toString().data(),
										                  label.data(),
										                  skipto);
										continue;
									}
									// create and modify filter for rule
									// XXX: we assume that filter's src/dst wasn't initialized
									ref_t<filter_t> filter = new filter_t(rulep);
									if (rulep->src_targ)
									{
										filter->src = new filter_network_t(prefix);
									}
									else
									{
										filter->dst = new filter_network_t(prefix);
									}
									auto& ruleref = yanet_rules.emplace_back(filter, rulep->ruleno, skipto);
									ruleref.ids.push_back(auto_id++);
									// add a hint in the comment for user where are we jumping to
									ruleref.comment = label;
									ACL_DBGMSG("expand rule " << rulep->ruleno << ": " << ruleref.to_string());
								}
								// don't insert original rule
								continue;
							}
							// skipto tablearg from .... via table(X)
							const auto& table = std::get<ipfw::tables::table_type_t>(
							        configp->m_tables[rulep->targ_name]);
							const auto& ifaces = std::get<ipfw::tables::ifname_t>(table);
							// create single rule_t(filter, ruleno, skipto) for each ifname
							for (const auto& [ifname, label] : ifaces)
							{
								if (label.empty())
								{
									YANET_LOG_WARNING("%s: rule %u: expanding error: empty label for ifname %s\n",
									                  __func__,
									                  rulep->ruleno,
									                  ifname.data());
									continue;
								}
								// resolve label into ruleno
								const auto& search = configp->m_labels.find(label);
								if (search == configp->m_labels.end())
								{
									YANET_LOG_WARNING("%s: rule %u: expanding error: label %s not found\n",
									                  __func__,
									                  rulep->ruleno,
									                  label.data());
									continue;
								}
								auto skipto = std::get<unsigned int>(search->second);
								// backwards skipto is not allowed
								if (skipto <= rulep->ruleno)
								{
									YANET_LOG_WARNING("%s: rule %u: attempt to jump backwards: %s -> %s (%u)\n",
									                  __func__,
									                  rulep->ruleno,
									                  ifname.data(),
									                  label.data(),
									                  skipto);
									continue;
								}

								auto& ruleref = yanet_rules.emplace_back(new filter_t(rulep), rulep->ruleno, skipto);
								// add ifname to rule
								ruleref.via.insert(ifname);
								ruleref.ids.push_back(auto_id++);
								// add a hint in the comment for user where are we jumping to
								ruleref.comment = label;
								ACL_DBGMSG("expand rule " << rulep->ruleno << ": " << ruleref.to_string());
							}
							// don't insert original rule
							continue;
						}
						// simple skipto rules are handled as usual
						[[fallthrough]];
					case ipfw::rule_action_t::ALLOW:
					case ipfw::rule_action_t::DUMP:
					case ipfw::rule_action_t::DENY:
					case ipfw::rule_action_t::CHECKSTATE:
					case ipfw::rule_action_t::STATETIMEOUT:
					case ipfw::rule_action_t::HITCOUNT:
					{
						// handle only meaning rules
						auto& ruleref = yanet_rules.emplace_back(rulep, configp);
						ACL_DBGMSG("add rule " << rulep->ruleno << ": " << ruleref.to_original_string());
					}
					break;
					default:
						// skip rules with unsupported action
						YANET_LOG_WARNING("%s: rule %u: unsupported action: %s\n",
						                  __func__,
						                  rulep->ruleno,
						                  rulep->text.data());
						continue;
				}
			}
		}
		// add explicit skipto to DISPATCHER
		unsigned int last_ruleno = 1;
		if (!rules.empty())
		{
			last_ruleno = rules.rbegin()->first;
		}
		auto& ruleref = rules[last_ruleno].emplace_back(nullptr, last_ruleno, DISPATCHER);
		ACL_DBGMSG("add last rule " << last_ruleno << ": " << ruleref.to_string());
	}
};

static bool unwind_dispatcher(const dispatcher_rules_t& dispatcher, const ref_t<filter_t>& filter, const std::string& iface, ids_t& ids, std::vector<rule_t>& rules, bool log);
static bool unwind(int64_t start_from, firewall_rules_t& fw, const dispatcher_rules_t& dispatcher, const ref_t<filter_t>& filter, const std::string& iface, ids_t& ids, std::vector<rule_t>& rules, bool log, size_t recursion_limit);
std::vector<rule_t> unwind_used_rules(const std::map<std::string, controlplane::base::acl_t>& acls,
                                      const iface_map_t& iface_map,
                                      ref_t<filter_t> filter,
                                      result_t& result);
std::vector<rule_t> unwind_rules(firewall_rules_t& fw, const dispatcher_rules_t& dispatcher, const ref_t<filter_t>& filter, const std::string& iface);

static inline auto skip_rule(const rule_t& rule,
                             const ref_t<filter_t>& filter,
                             const std::string& iface)
{
	// skip rules that don't match given filter
	if (filter && rule.filter && !compatible(filter, rule.filter))
	{
		return true;
	}
	// skip rules whose via-interfaces do not match given iface
	if (!rule.via.empty() && rule.via.find(iface) == rule.via.end())
	{
		return true;
	}
	return false;
}

static inline auto is_term_filter(const ref_t<filter_t>& filter)
{
	return (!filter || (!filter->src && !filter->dst && !filter->flags && !filter->proto));
}

// gather matching rules from dispatcher
static bool unwind_dispatcher(const dispatcher_rules_t& dispatcher,
                              const ref_t<filter_t>& filter,
                              const std::string& iface,
                              ids_t& ids,
                              std::vector<rule_t>& rules,
                              bool log)
{
	auto idSize = ids.size();
	for (const auto& rule : dispatcher.rules)
	{
		ACL_DBGMSG("checking rule: " << rule.to_string());
		if (skip_rule(rule, filter, iface))
		{
			continue;
		}

		ref_t<filter_t> result_filter = filter & rule.filter;
		if (result_filter.is_none())
		{
			continue;
		}

		ids.insert(ids.end(), rule.ids.begin(), rule.ids.end());
		rules.emplace_back(std::move(result_filter),
		                   std::get<common::globalBase::tFlow>(rule.action),
		                   ids,
		                   log || rule.log);
		ids.resize(idSize);

		ACL_DBGMSG("gathered...");
		if (is_term_filter(rule.filter) && (rule.is_term() || rule.is_skipto()))
		{
			ACL_DBGMSG("terminating filter...");
			break;
		}
	}
	// return explicit true
	// we have already reached DISPATCHER's rules,
	// thus there is no need to try another rules
	return true;
}

static bool unwind(int64_t start_from, firewall_rules_t& fw, const dispatcher_rules_t& dispatcher, const ref_t<filter_t>& filter, const std::string& iface, ids_t& ids, std::vector<rule_t>& rules, bool log, size_t recursion_limit)
{
	if (recursion_limit > 1000)
	{
		throw std::out_of_range("to many enclosed sections");
	}
	if (start_from == DISPATCHER)
	{
		// we should not be herer, just in case.
		return true;
	}

	auto idSize = ids.size();
	auto term_rule = false;
	auto [ruleno_it, inserted] = fw.rules.try_emplace(start_from);

	if (inserted)
	{
		ACL_DBGMSG("skipto to empty rule " + std::to_string(start_from));
	}
	for (; ruleno_it != fw.rules.end(); ruleno_it++)
	{
		for (const auto& rule : ruleno_it->second)
		{
			ACL_DBGMSG("checking rule " << ruleno_it->first << ": " << rule.to_original_string());
			if (skip_rule(rule, filter, iface))
			{
				continue;
			}

			ref_t<filter_t> result_filter = filter & rule.filter;
			if (result_filter.is_none())
			{
				continue;
			}
			ids.insert(ids.end(), rule.ids.begin(), rule.ids.end());

			ACL_DBGMSG("advancing further...");
			std::visit([&](const auto& action) {
				using T = std::decay_t<decltype(action)>;

				if constexpr (std::is_same_v<T, int64_t>)
				{
					// handle skipto && allow action
					start_from = action;
					if (start_from != DISPATCHER)
					{
						ACL_DBGMSG("skipto " << start_from);
						term_rule = unwind(start_from, fw, dispatcher, result_filter, iface, ids, rules, log || rule.log, recursion_limit + 1);
						// if we have reached DISPATCHER, it will be handled next
					}
					if (start_from == DISPATCHER)
					{
						ACL_DBGMSG("go to dispatcher...");
						term_rule = unwind_dispatcher(dispatcher, result_filter, iface, ids, rules, log || rule.log);
					}
				}
				else
				{
					// Handle other types by emplacing them directly into rules
					rules.emplace_back(std::move(result_filter), action, ids, log || rule.log);
					ACL_DBGMSG(typeid(T).name() << " gathered...");
				}
			},
			           rule.action);

			ids.resize(idSize);
			if (is_term_filter(rule.filter) && (rule.is_term() || rule.is_skipto()))
			{
				ACL_DBGMSG("terminating filter...");
				return true;
			}
		}
	}
	return term_rule;
}

std::vector<rule_t> unwind_rules(firewall_rules_t& fw,
                                 const dispatcher_rules_t& dispatcher,
                                 const ref_t<filter_t>& filter,
                                 const std::string& iface)
{
	auto start_from = fw.rules.begin()->first;
	std::vector<rule_t> rules;
	ids_t ids;

	ACL_DBGMSG("unwinding iface " << iface << ", filter: " << (filter ? filter->to_string() : "empty"));
	unwind(start_from, fw, dispatcher, filter, iface, ids, rules, false, 0);
	return rules;
}

iface_map_t ifaceMapping(std::map<std::string, controlplane::base::logical_port_t> logicalPorts,
                         std::map<std::string, controlplane::route::config_t> routes)
{
	iface_map_t ret;

	for (const auto& [name, port] : logicalPorts)
	{
		if (port.flow.type == common::globalBase::eFlowType::acl_ingress)
		{
			ret[port.flow.data.aclId].emplace(true, name);
		}
	}

	for (const auto& [route_name, route] : routes)
	{
		GCC_BUG_UNUSED(route_name);
		for (const auto& [name, iface] : route.interfaces)
		{
			GCC_BUG_UNUSED(name);
			ret[iface.aclId].emplace(false, iface.nextModule);
		}
	}

	return ret;
}

// used by acl_lookup
unwind_result unwind(const std::map<std::string, controlplane::base::acl_t>& acls,
                     const iface_map_t& ifaces,
                     [[maybe_unused]] const std::optional<std::string>& module,
                     const std::optional<std::string>& direction,
                     const std::optional<std::string>& network_source,
                     const std::optional<std::string>& network_destination,
                     const std::optional<std::string>& fragment,
                     const std::optional<std::string>& protocol,
                     const std::optional<std::string>& transport_source,
                     const std::optional<std::string>& transport_destination,
                     const std::optional<std::string>& transport_flags,
                     const std::optional<std::string>& in_recordstate)
{
	unwind_result result;

	try
	{
		ref_t<filter_id_t> acl_id;
		ref_t<filter_id_t> filter_dir;

		ref_t<filter_network_t> filter_network_source;
		ref_t<filter_network_t> filter_network_destination;
		ref_t<filter_prm8_t> filter_fragment;
		ref_t<filter_prm8_t> filter_protocol;
		ref_t<filter_prm16_t> filter_transport_source;
		ref_t<filter_prm16_t> filter_transport_destination;
		ref_t<filter_prm8_t> filter_transport_flags;

		if (direction)
		{
			if (*direction == "in")
			{
				filter_dir = new filter_id_t(0);
			}
			else if (*direction == "out")
			{
				filter_dir = new filter_id_t(1);
			}
		}

		if (network_source)
		{
			filter_network_source = new filter_network_t(*network_source);
		}

		if (network_destination)
		{
			filter_network_destination = new filter_network_t(*network_destination);
		}

		if (fragment)
		{
			filter_fragment = new filter_prm8_t(std::stoul(*fragment, nullptr, 0));
		}

		if (protocol)
		{
			filter_protocol = new filter_prm8_t(std::stoul(*protocol, nullptr, 0));
		}

		if (transport_source)
		{
			filter_transport_source = new filter_prm16_t(std::stoul(*transport_source, nullptr, 0));
		}

		if (transport_destination)
		{
			filter_transport_destination = new filter_prm16_t(std::stoul(*transport_destination, nullptr, 0));
		}

		if (transport_flags)
		{
			filter_transport_flags = new filter_prm8_t(std::stoul(*transport_flags, nullptr, 0));
		}

		ref_t<filter_proto_t> transport = new filter_proto_t(filter_protocol, filter_transport_source, filter_transport_destination, filter_transport_flags);
		ref_t<filter_t> filter = new filter_t(acl_id, filter_network_source, filter_network_destination, filter_fragment, transport, filter_dir, nullptr);

		result_t unwind_result;
		auto rules = unwind_used_rules(acls, ifaces, filter, unwind_result);

		std::map<tAclId, std::string> ifaces_map;
		for (const auto& [name, aclId] : unwind_result.in_iface_map)
		{
			ifaces_map[aclId] += name + " ";
		}
		for (const auto& [name, aclId] : unwind_result.out_iface_map)
		{
			ifaces_map[aclId] += name + " ";
		}

		for (auto& rule : rules)
		{
			if (auto flow = std::get_if<common::globalBase::tFlow>(&rule.action))
			{
				std::string module = "any";
				std::string direction = "any";
				std::string network_source = "any";
				std::string network_destination = "any";
				std::string fragment = "any";
				std::string protocol = "any";
				std::string transport_source = "any";
				std::string transport_destination = "any";
				std::string transport_flags = "any";
				std::string recordstate = "false";
				std::string next_module = "any";
				std::string log = rule.log ? "true" : "false";

				if (rule.filter)
				{
					if (rule.filter->acl_id)
					{
						auto name = ifaces_map[rule.filter->acl_id->val];
						module = name.empty() ? rule.filter->acl_id->to_string() : name;
					}

					if (rule.filter->dir)
					{
						direction = rule.filter->dir->to_string();
					}

					if (rule.filter->src)
					{
						network_source = rule.filter->src->to_string();
					}

					if (rule.filter->dst)
					{
						network_destination = rule.filter->dst->to_string();
					}

					if (rule.filter->flags)
					{
						fragment = rule.filter->flags->to_string();
					}

					if (rule.filter->proto)
					{
						if (rule.filter->proto->type)
						{
							protocol = rule.filter->proto->type->to_string();
						}

						if (rule.filter->proto->prm1)
						{
							transport_source = rule.filter->proto->prm1->to_string();
						}

						if (rule.filter->proto->prm2)
						{
							transport_destination = rule.filter->proto->prm2->to_string();
						}

						if (rule.filter->proto->prm3)
						{
							transport_flags = rule.filter->proto->prm3->to_string();
						}
					}

					if (rule.filter->recordstate)
					{
						recordstate = "true";
					}

					if (in_recordstate &&
					    recordstate != *in_recordstate)
					{
						continue;
					}
				}

				next_module = std::string(eFlowType_toString(flow->type)) + "(" + std::to_string(flow->getId()) + ")";

				std::string ids;
				bool first = true;
				for (auto id : rule.ids)
				{
					if (!first)
					{
						ids += ", ";
					}
					first = false;
					ids += std::to_string(id);
				}

				result.emplace_back(module,
				                    direction,
				                    network_source,
				                    network_destination,
				                    fragment,
				                    protocol,
				                    transport_source,
				                    transport_destination,
				                    transport_flags,
				                    recordstate,
				                    next_module,
				                    ids,
				                    log);
			}
		}
	}
	catch (const std::exception& ex)
	{
		YANET_LOG_WARNING("acl_unwind: dispatcher compilation error \"%s\"\n", ex.what());
	}
	catch (const std::string& ex)
	{
		YANET_LOG_WARNING("acl_unwind: dispatcher compilation error \"%s\"\n", ex.data());
	}
	catch (...)
	{
		YANET_LOG_WARNING("acl_unwind: unknown dispatcher compilation error\n");
	}

	return result;
}

tCounterId get_or_create_counter_id(const ids_t& ids,
                                    std::map<ids_t, uint32_t>& ids_map_map,
                                    std::vector<ids_t>& ids_map,
                                    std::set<ids_t>& ids_overflow)
{
	auto it = ids_map_map.find(ids);
	if (it != ids_map_map.end())
		return it->second;

	if (ids_map.size() < YANET_CONFIG_ACL_COUNTERS_SIZE)
	{
		auto id = ids_map.size();
		ids_map.push_back(ids);
		ids_map_map.emplace(ids, id);
		return id;
	}
	else
	{
		ids_overflow.insert(ids);
		return 0;
	}
}

std::vector<rule_t> unwind_used_rules(const std::map<std::string, controlplane::base::acl_t>& acls,
                                      const iface_map_t& iface_map,
                                      ref_t<filter_t> filter,
                                      result_t& result)
{
	std::unordered_map<std::vector<rule_t>, tAclId> rules_map(acls.size());

	size_t acls_count = 0;
	for (const auto& [moduleName, acl] : acls)
	{
		UNUSED(moduleName);
		if (acl.aclId >= acls_count)
		{
			acls_count = acl.aclId + 1;
		}
	}

	/// ids_t to index map
	std::map<ids_t, uint32_t> ids_map_map;
	ids_map_map.emplace(ids_t(), 0);

	result.ids_map.clear();
	result.ids_map.emplace_back();
	std::set<ids_t> ids_overflow;

#ifdef ACL_DEBUG
	uint32_t disp_id = FW_DISPATCHER_START_ID;
#endif
	uint32_t rule_id = FW_GENRULES_START_ID;
	for (const auto& [moduleName, acl] : acls)
	{
		auto it = iface_map.find(acl.aclId);
		if (it == iface_map.end())
		{
			YANET_LOG_WARNING("there is no interfaces for acl %s:%d\n", moduleName.c_str(), acl.aclId);
			continue;
		}

		// prepare firewall rules in YaNET format
		firewall_rules_t fw(acl, rule_id);
		for (auto& [ruleno, yanet_rules] : fw.rules)
		{
			auto& result_rules = result.rules[ruleno];
			for (auto& rule : yanet_rules)
			{
#ifdef ACL_DEBUG
				// assign rule id to unhide some rules
				if (rule.ids.empty())
				{
					rule.ids.push_back(rule_id++);
				}
#endif
				// add text to all rules
				if (!rule.ids.empty())
				{
					auto orig_text = rule.to_original_string();
					result_rules.emplace_back(std::make_tuple(
					        rule.ids[0],
					        rule.to_string(),
					        orig_text));
				}
				ACL_DBGMSG("rule " << ruleno << ": " << rule.to_original_string());
			}
		}
#ifdef ACL_DEBUG
		if (rule_id >= FW_DISPATCHER_START_ID)
		{
			throw std::runtime_error("internal error: generated rule id overlaps dispacher's id.");
		}
#endif
		// prepare dispatcher rules in YaNET format
		// and generate text representation for them
		dispatcher_rules_t dispatcher(acl);
		for (auto& rule : dispatcher.rules)
		{
#ifdef ACL_DEBUG
			if (rule.ids.empty())
			{
				rule.ids.push_back(disp_id++);
			}
			// add text to all rules
			if (!rule.ids.empty())
#endif
			{
				result.dispatcher.emplace_back(
#ifdef ACL_DEBUG
				        rule.ids[0],
#else
				        FW_DISPATCHER_START_ID,
#endif
				        rule.to_string(),
				        std::string());
			}
			ACL_DBGMSG("dispatcher rule: " << rule.to_string());
		}

		auto aclId = acl.aclId;
		for (auto& [dir, iface] : it->second)
		{
			ref_t<filter_id_t> acl_id = new filter_id_t(aclId);
			ref_t<filter_id_t> direction(new filter_id_t(dir ? 0 : 1));

			ref_t<filter_t> start_filter = new filter_t(acl_id, nullptr, nullptr, nullptr, nullptr, direction, nullptr);
			start_filter = start_filter & filter;

			auto rules = unwind_rules(fw, dispatcher, start_filter, iface);
			for (auto rules_iter = rules.begin(); rules_iter != rules.end(); /* manual increment below */)
			{
				auto& rule = *rules_iter;
				bool remove_rule = false;

				std::visit(
				        [&](auto& action) {
					        using T = std::decay_t<decltype(action)>;

					        // Assign counter_id to all relevant actions
					        if constexpr (std::is_same_v<T, common::globalBase::tFlow> ||
					                      std::is_same_v<T, common::acl::check_state_t> ||
					                      std::is_same_v<T, common::acl::dump_t> ||
					                      std::is_same_v<T, common::acl::hit_count_t>)
					        {
						        action.counter_id = get_or_create_counter_id(rule.ids, ids_map_map, result.ids_map, ids_overflow);
					        }

					        if constexpr (std::is_same_v<T, common::globalBase::tFlow>)
					        {
						        if (rule.filter->recordstate)
						        {
							        action.flags |= (int)common::globalBase::eFlowFlags::recordstate;
						        }
						        if (rule.log)
						        {
							        action.flags |= (int)common::globalBase::eFlowFlags::log;
						        }
					        }
					        else if constexpr (std::is_same_v<T, common::acl::dump_t>)
					        {
						        if (!action.dump_tag.empty())
						        {
							        if (result.dump_id_to_tag.size() >= YANET_CONFIG_DUMP_ID_TO_TAG_SIZE &&
							            result.tag_to_dump_id.find(action.dump_tag) == result.tag_to_dump_id.end())
							        {
								        // We should remove this rule because the dump_id would exceed the limit
								        remove_rule = true;
							        }
							        else
							        {
								        auto it = result.tag_to_dump_id.find(action.dump_tag);
								        if (it == result.tag_to_dump_id.end())
								        {
									        result.dump_id_to_tag.emplace_back(action.dump_tag);
									        it = result.tag_to_dump_id.emplace_hint(it, action.dump_tag, result.dump_id_to_tag.size());
								        }
								        action.dump_id = it->second;
							        }
						        }
					        }
					        // No specific logic needed for the rest of the actions like state_timeout_t
					        // Most notably, we don't need counter_id for them since they are not actually presented as an action
					        // that packet "goes through". In case of state_timeout_t, its optimized so the resulting timeout
					        // is already presented in the "flow" action.
				        },
				        rule.action);

				if (remove_rule)
					rules_iter = rules.erase(rules_iter);
				else
					++rules_iter;
			}

			auto [it, inserted] = rules_map.try_emplace(std::move(rules), aclId);
			if (inserted)
			{
				bool new_acl = aclId != acl.aclId;
				if (new_acl)
				{
					acls_count++;
				}
				aclId = acls_count;
			}
			(dir ? result.in_iface_map : result.out_iface_map)[iface] = it->second;
			result.acl_map[acl.aclId].insert(it->second);

			YANET_LOG_DEBUG("%s via %s -> acl %s:%d %lu rules\n", dir ? "in" : "out", iface.c_str(), moduleName.c_str(), it->second, it->first.size());
		}
	}

	YANET_LOG_DEBUG("acl_counters: %lu\n", result.ids_map.size());
	if (ids_overflow.size() != 0)
	{
		YANET_LOG_ERROR("Overflow of rule count limit by %lu\n", ids_overflow.size());
	}

	std::vector<rule_t> rules;
	for (const auto& [r, acl] : rules_map)
	{
		UNUSED(acl);
		std::copy(r.begin(), r.end(), std::back_inserter(rules));
	}

	YANET_LOG_DEBUG("result acl count is %lu and rules size is %lu\n", acls_count, rules.size());

	return rules;
}

void compile(const std::map<std::string, controlplane::base::acl_t>& acls,
             const iface_map_t& iface_map,
             result_t& result)
{
	try
	{
		acl::compiler_t compiler; ///< @todo: move to module

		YANET_LOG_INFO("acl::compile: unwind\n");
		auto rules_used = unwind_used_rules(acls, iface_map, nullptr, result);
		compiler.compile(rules_used, result);
	}
	catch (const std::exception& ex)
	{
		YANET_LOG_ERROR("dispatcher compilation error \"%s\"\n", ex.what());
		throw;
	}
	catch (const std::string& ex)
	{
		YANET_LOG_ERROR("dispatcher compilation error \"%s\"\n", ex.data());
		throw;
	}
	catch (...)
	{
		YANET_LOG_ERROR("unknown dispatcher compilation error\n");
		throw;
	}
}

/// @todo: move
uint8_t string_to_proto(const std::string& string)
{
	static std::map<std::string, uint8_t> protocols = {{"ip", IPPROTO_IP},
	                                                   {"icmp", IPPROTO_ICMP},
	                                                   {"icmpv6", IPPROTO_ICMPV6},
	                                                   {"ipip", IPPROTO_IPIP},
	                                                   {"tcp", IPPROTO_TCP},
	                                                   {"egp", IPPROTO_EGP},
	                                                   {"udp", IPPROTO_UDP},
	                                                   {"ipv6", IPPROTO_IPV6},
	                                                   {"gre", IPPROTO_GRE},
	                                                   {"esp", IPPROTO_ESP},
	                                                   {"sctp", IPPROTO_SCTP}};

	auto it = protocols.find(string);
	if (it == protocols.end())
	{
		it = protocols.emplace_hint(it, string, std::stoul(string, nullptr, 0));
	}

	return it->second;
}

std::set<uint32_t> lookup(const std::map<std::string, controlplane::base::acl_t>& acls,
                          const iface_map_t& ifaces,
                          [[maybe_unused]] const std::optional<std::string>& module,
                          const std::optional<std::string>& direction,
                          const std::optional<std::string>& network_source,
                          const std::optional<std::string>& network_destination,
                          const std::optional<std::string>& fragment,
                          const std::optional<std::string>& protocol,
                          const std::optional<std::string>& transport_source,
                          const std::optional<std::string>& transport_destination)
{
	std::set<uint32_t> result;

	try
	{
		ref_t<filter_id_t> acl_id;
		ref_t<filter_id_t> filter_dir;

		ref_t<filter_network_t> filter_network_source;
		ref_t<filter_network_t> filter_network_destination;
		ref_t<filter_prm8_t> filter_fragment;
		ref_t<filter_prm8_t> filter_protocol;
		ref_t<filter_prm16_t> filter_transport_source;
		ref_t<filter_prm16_t> filter_transport_destination;
		ref_t<filter_prm8_t> filter_transport_flags;

		if (direction)
		{
			if (*direction == "in")
			{
				filter_dir = new filter_id_t(0);
			}
			else if (*direction == "out")
			{
				filter_dir = new filter_id_t(1);
			}
		}

		if (network_source)
		{
			filter_network_source = new filter_network_t(*network_source);
		}

		if (network_destination)
		{
			filter_network_destination = new filter_network_t(*network_destination);
		}

		if (fragment)
		{
			filter_fragment = new filter_prm8_t(std::stoul(*fragment, nullptr, 0));
		}

		if (protocol)
		{
			filter_protocol = new filter_prm8_t(string_to_proto(*protocol));
		}

		if (transport_source)
		{
			filter_transport_source = new filter_prm16_t(std::stoul(*transport_source, nullptr, 0));
		}

		if (transport_destination)
		{
			filter_transport_destination = new filter_prm16_t(std::stoul(*transport_destination, nullptr, 0));
		}

		ref_t<filter_proto_t> transport = new filter_proto_t(filter_protocol, filter_transport_source, filter_transport_destination, filter_transport_flags);
		ref_t<filter_t> filter = new filter_t(acl_id, filter_network_source, filter_network_destination, filter_fragment, transport, filter_dir, nullptr);

		result_t unwind_result;
		auto rules_used = unwind_used_rules(acls, ifaces, filter, unwind_result);

		acl::compiler_t compiler;
		compiler.compile(rules_used, unwind_result);

		for (const auto rule_id : compiler.used_rules)
		{
			for (auto id : rules_used[rule_id].ids)
			{
				result.emplace(id);
			}
		}
	}
	catch (const std::exception& ex)
	{
		YANET_LOG_WARNING("acl_lookup: dispatcher compilation error \"%s\"\n", ex.what());
	}
	catch (const std::string& ex)
	{
		YANET_LOG_WARNING("acl_lookup: dispatcher compilation error \"%s\"\n", ex.data());
	}
	catch (...)
	{
		YANET_LOG_WARNING("acl_lookup: unknown dispatcher compilation error\n");
	}

	return result;
}

} // namespace acl
