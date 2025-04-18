#include "acl_total_table.h"
#include "acl_compiler.h"

using namespace acl::compiler;

total_table_t::total_table_t(compiler_t* compiler) :
        compiler(compiler)
{
	clear();
}

void total_table_t::clear()
{
	table.clear();
}

void total_table_t::collect(const unsigned int rule_id, const filter& filter)
{
	auto [acl_id, filter_id] = filter;
	filter_id_acl_id_rule_ids[filter_id][acl_id].push_back(rule_id);
}

void total_table_t::prepare()
{
}

/**
 * @brief Compiles the total table by processing groups and their associated ACL rules.
 *
 * This function iterates through all threads, groups, and their respective ACL rules,
 * and fills the total table with rules. The rules are processed until a terminating rule
 * is encountered or all rules have been processed. If no terminating rule is found, a
 * default "drop" action is appended at the end (see `value_t::compile()`).
 */
void total_table_t::compile()
{
	YANET_LOG_DEBUG("Compiling total table\n");

	for (auto& thread : compiler->transport_table.threads)
	{
		for (const auto& [group, filter_ids] : thread.group_id_filter_ids)
		{
			YANET_LOG_DEBUG("Processing group %u:\n", group);

			std::unordered_map<unsigned, std::set<unsigned>> acl_id_to_rule_ids;

			for (const auto& filter_id : filter_ids)
			{
				auto it = filter_id_acl_id_rule_ids.find(filter_id);
				if (it == filter_id_acl_id_rule_ids.end())
					continue;

				for (const auto& [acl_id, rile_ids] : it->second)
				{
					acl_id_to_rule_ids[acl_id].insert(rile_ids.begin(), rile_ids.end());
				}
			}

			for (auto& [acl_id, rule_ids] : acl_id_to_rule_ids)
			{
				common::acl::total_key_t key{acl_id, group};

				YANET_LOG_DEBUG("\tFilling key {%u, %u}\n", key.transport_id, key.acl_id);

				// At this point there's nothing in this group hence we should add at least one rule.
				// Do it here, cause there are a decent chance that there will be only one rule or it
				// will be terminating, so the following loop will be unnecessary.
				auto rule_iter = rule_ids.begin();
				const auto& first_rule = compiler->rules[*rule_iter];
				YANET_LOG_DEBUG("\t\tAdding rule %u\n", first_rule.rule_id);
				table[key] = compiler->value.collect(first_rule.value_filter_id);
				compiler->used_rules.push_back(first_rule.rule_id);

				if (first_rule.terminating)
					continue;

				YANET_LOG_DEBUG("\t\tThat rule was not terminating, so continue\n");

				for (++rule_iter; rule_iter != rule_ids.end(); ++rule_iter)
				{
					const auto& rule = compiler->rules[*rule_iter];
					compiler->value.append_to_last(rule.value_filter_id);
					compiler->used_rules.push_back(rule.rule_id);
					YANET_LOG_DEBUG("\t\tAppending rule %u\n", rule.rule_id);

					if (rule.terminating)
					{
						YANET_LOG_DEBUG("\t\tThat rule was terminating, so break from processing for this acl_id and group\n");
						break;
					}
				}
			}
		}
	}
}
