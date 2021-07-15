//
// Created by sdn on 9/20/20.
//

#ifndef BM_BM_STATEFUL_TABLES_H
#define BM_BM_STATEFUL_TABLES_H

#include "control_flow.h"
#include "match_tables.h"
#include "flow_context.h"
#include "logger.h"
#include "match_units.h"

namespace bm {
    class FlowTable : public MatchTableAbstract {
    public:
      struct Entry : public EntryCommon {
        const ActionFn *action_fn;
        ActionData action_data;
      };

    public:
      FlowTable(const std::string &name, p4object_id_t id,
                std::unique_ptr<MatchUnitAbstract<ActionEntry>> match_unit,
                const std::vector<MatchKeyBuilder> &match_key_builder,
                bool with_counters = false, bool with_ageing = false,
                uint64_t idle_timeout = 0);

      MatchTableType get_table_type() const override {
        return MatchTableType::STATEFUL;
      }

      const ActionEntry &lookup(const Packet &pkt, bool *hit,
                                entry_handle_t *handle,
                                const ControlFlowNode **next_node) override;

      size_t get_num_entries() const override {
        return match_unit->get_num_entries();
      }

      std::vector<Entry> get_entries() const;

      bool is_valid_handle(entry_handle_t handle) const override {
        return match_unit->valid_handle(handle);
      }

      MatchErrorCode add_entry(const std::vector<MatchKeyParam> &match_key,
                               ActionEntry action,
                               entry_handle_t *handle);

      MatchErrorCode delete_entry(entry_handle_t handle);

      MatchErrorCode get_action_entry(entry_handle_t handle, const ActionEntry **action);

      MatchErrorCode get_entry(entry_handle_t handle, Entry *entry) const;

      MatchErrorCode get_entry_from_key(const std::vector<MatchKeyParam> &match_key,
                                        Entry *entry, int priority = 1) const;

      entry_handle_t get_last_handle() const { return last_handle; };

      void set_entry_flow_ctx_str(entry_handle_t handle, const std::string& dump) const;


    public:
      static std::unique_ptr<FlowTable> create(
          const std::string &name,
          p4object_id_t id,
          size_t size, const std::vector<MatchKeyBuilder> &match_key_builder,
          LookupStructureFactory *lookup_factory,
          bool with_counters, bool with_ageing, uint64_t idle_timeout);

    private:
      void reset_state_(bool reset_default_entry) override;

      void serialize_(std::ostream *out) const override;
      void deserialize_(std::istream *in, const P4Objects &objs) override;

      MatchErrorCode dump_entry_(std::ostream *out,
                                 entry_handle_t handle) const override;

      void set_default_default_entry_() override;

      MatchErrorCode get_entry_(entry_handle_t handle, Entry *entry) const;

    private:
      ActionEntry default_entry{};
      std::unique_ptr<MatchUnitAbstract<ActionEntry> > match_unit;
      const ActionFn *const_default_action{nullptr};
      const std::vector<MatchKeyBuilder> match_key_builders;
      entry_handle_t last_handle;
      uint64_t idle_timeout;
    };


    class StatefulTable : public ControlFlowNode {
    public:
        StatefulTable(const std::string &name, p4object_id_t id,
                         std::unique_ptr<FlowTable> match_table,
                         std::unique_ptr<FlowContext> flow_context);

        const ControlFlowNode *operator()(Packet *pkt) const override;

        MatchTableAbstract *get_match_table() { return match_table.get(); };

        void update_flow_context(PHV *phv) const override;

        void delete_entry(entry_handle_t handle);

        bool is_stateful() const override { return true; };

        void apply_timer(Packet *pkt);

        std::string dump_flow_context(entry_handle_t handle) const;

    public:
        static std::unique_ptr<StatefulTable> create_stateful_table(
            const std::string &name, p4object_id_t id,
            size_t size, const std::vector<MatchKeyBuilder> &match_key_builders,
            bool with_counters, bool with_ageing, uint64_t idle_timeout,
            LookupStructureFactory *lookup_factory, HeaderType *header) {

            std::unique_ptr<FlowTable> match_table = FlowTable::create(
                    name, id, size, match_key_builders, lookup_factory,
                    with_counters, with_ageing, idle_timeout);

            BMLOG_DEBUG("Created State table {}", match_table->get_name());

            std::unique_ptr<FlowContext> flow_ctx = std::unique_ptr<FlowContext>(
                                                    new FlowContext(header, size));

            return std::unique_ptr<StatefulTable> (
                    new StatefulTable(name, id, std::move(match_table), std::move(flow_ctx)));

        }

    private:
        std::unique_ptr<FlowTable> match_table;
        std::unique_ptr<FlowContext> flow_context;

        void set_flow_context(Packet *pkt, entry_handle_t handle) const;

    };

    struct StatefulTimer {
      std::string table_name;
      uint64_t granularity;

      StatefulTimer(const std::string &tname, const uint64_t gran) {
        table_name = tname;
        granularity = gran;
      }
    };


}

#endif //BM_BM_STATEFUL_TABLES_H
