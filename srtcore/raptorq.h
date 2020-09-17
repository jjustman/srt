/*
 * jjustman@onemediallc.com
 * 2020-09-16
 * 
 */


#ifndef INC_SRT_RAPTORQ_H
#define INC_SRT_RAPTORQ_H

#include <string>
#include <map>
#include <vector>
#include <deque>
#include <utility>      // std::pair, std::make_pair

using namespace std;

#include "packetfilter_api.h"

#ifndef __LIBATSC3_ANDROID__
#include <CodornicesRq/rq_api.h>

/*

TX sender
./srt-live-transmit  -v -r 1000 -s 1000 "udp://239.239.239.239:30000?rcvbuf=67108864&adapter=20.20.20.25&mode=listener" "srt://:31337?mode=listener&latency=500&packetfilter=raptorq,source_block_size:512000,symbol_size:1372,recovery_symbols:16"


RX recovery
./srt-live-transmit -v -r 1000 -s 1000 "srt://localhost:31337" "udp://239.239.239.239:30001?rcvbuf=67108864&adapter=20.20.20.25"



 */

class IRaptorQSettings {
public:
	int getKSourceSymbols() { return m_source_symbols; }
	int getSymbolSize() { return m_symbol_size; }

protected:
	size_t 	m_source_block_size; //e.g. 256KB
	size_t	m_symbol_size;		//should be max(packetlen) and frames padded if < value
	int		m_recovery_symbols;		//how many recovery symbols (*m_symbol_size) should be generated/transmitted as control packets

	int		m_source_symbols;		//computed as m_source_block_size / m_symbol_size
};

class IRaptorQCoder : public IRaptorQSettings {
public:
	virtual void init(size_t source_block_size, size_t symbol_size, int recovery_symbols) = 0;

};

class RaptorQEncoder : public IRaptorQCoder {
public:
	virtual void init(size_t source_block_size, size_t symbol_size, int recovery_symbols);
	 ~RaptorQEncoder();

	 void encode(uint32_t sbn);

//private:

	size_t nInterWorkMemSize = 0, nInterProgMemSize = 0, nInterSymNumForExec = 0;

	RqInterWorkMem* pInterWorkMem;
	RqInterProgram* pInterProgMem;

	size_t nInterSymMemSize;
	RqInterWorkMem* pInterSymMem;

	size_t nInSymMemSize;
	uint8_t* pcInSymMem;

	size_t nOutWorkMemSize, nOutProgMemSize;

	RqOutWorkMem* pOutWorkMem;
	RqOutProgram* pOutProgMem;

	size_t nOutSymMemSize;
	uint8_t* pOutSymMem;

	uint32_t nSbnPOutSysMem = 0;  			//keep track of our current sbn for packControlPacket generation
	int32_t	nControlPacketPosition = -1;	//keep track of our R index when flushing out packControlPacket

};

class RaptorQDecoder : public IRaptorQCoder {
public:
	virtual void init(size_t source_block_size, size_t symbol_size, int recovery_symbols);
	~RaptorQDecoder();

	void pushCPacket(uint32_t sbn, uint32_t esi, CPacket* cPacket);

	bool needsRQRecovery(uint32_t sbn);
	bool canPerformRQRecovery(uint32_t sbn);
	int getEsiSourceSize(uint32_t sbn);

	int executeRQRecovery(uint32_t sbn);
	void discardSbn(uint32_t sbn);

	pair<uint32_t, uint32_t> getRecoveredSbnSourceRepairCount(uint32_t sbn);

//private:

    size_t nInterWorkMemSize;
    size_t nInterProgMemSize;
    size_t nInterSymNumForExec;

    size_t nOutWorkMemSize;
	size_t nOutProgMemSize;

	int nMaxExtra;

    RqInterWorkMem* pInterWorkMem;
	RqInterProgram* pInterProgMem;

	size_t nInterSymMemSize;
	RqInterWorkMem* pInterSymMem;

	size_t nInSymMemSize;
	uint8_t* pcInSymMem;

	RqOutWorkMem* pOutWorkMem;
	RqOutProgram* pOutProgMem;

	size_t nOutSymMemSize;
	uint8_t* pOutSymMem;

	map<uint32_t, map<uint32_t, CPacket*>> sbnEsiCpacketSource;
	map<uint32_t, map<uint32_t, CPacket*>> sbnEsiCpacketRepair;
	map<uint32_t, pair<uint32_t, uint32_t>> recoveredSbnSourceRepairCount;


};

class RaptorQFilterBuiltin: public SrtPacketFilterBase, public IRaptorQSettings
{
    SrtFilterConfig cfg;

    RaptorQEncoder* encoder;
    RaptorQDecoder* decoder;

    // Configuration
    SRT_ARQLevel m_fallback_level;

public:


    RaptorQFilterBuiltin(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const std::string& confstr);

    // Sender side

    // This function creates and stores the FEC control packet with
    // a prediction to be immediately sent. This is called in the function
    // that normally is prepared for extracting a data packet from the sender
    // buffer and send it over the channel.
    virtual bool packControlPacket(SrtPacket& r_packet, int32_t seq) ATR_OVERRIDE;

    // This is called at the moment when the sender queue decided to pick up
    // a new packet from the scheduled packets. This should be then used to
    // continue filling the group, possibly followed by final calculating the
    // FEC control packet ready to send.
    virtual void feedSource(CPacket& r_packet) ATR_OVERRIDE;

    // Receiver side

    // This function is called at the moment when a new data packet has
    // arrived (no matter if subsequent or recovered). The 'state' value
    // defines the configured level of loss state required to send the
    // loss report.
    virtual bool receive(const CPacket& pkt, loss_seqs_t& loss_seqs) ATR_OVERRIDE;

    // Configuration

    // This is the size that is needed extra by packets operated by this corrector.
    // It should be subtracted from a current maximum value for SRTO_PAYLOADSIZE

    // The default FEC uses extra space only for FEC/CTL packet.
    // The timestamp clip is placed in the timestamp field in the header.
    // The payload contains:
    // - the length clip
    // - the flag spec
    // - the payload clip
    // The payload clip takes simply the current length of SRTO_PAYLOADSIZE.
    // So extra 4 bytes are needed, 2 for flags, 2 for length clip.

    // SBN / ESI should only be uint32_t and uint32_2, extraSize is 32 bit words

    static const size_t EXTRA_SIZE = 2; //8 bytes

    virtual SRT_ARQLevel arqLevel() ATR_OVERRIDE { return m_fallback_level; }

    int32_t firstSeqNum = -1;

    struct RaptorQ_FECHeader {
    	uint32_t	sbn;	//source block number (packet.getSeqNo / m_source_symbols)
    	uint32_t	esi;	//encoding symbol id
    };

    typedef SrtPacket PrivPacket;
    std::vector<PrivPacket>& rebuilt;

//    struct Group
//    {
//        int32_t base;     //< Sequence of the first packet in the group
//        size_t step;      //< by how many packets the sequence should increase to get the next packet
//        size_t drop;      //< by how much the sequence should increase to get to the next series
//        size_t collected; //< how many packets were taken to collect the clip
//
//        Group(): base(CSeqNo::m_iMaxSeqNo), step(0), drop(0), collected(0)
//        {
//        }
//
//        uint16_t length_clip;
//        uint8_t flag_clip;
//        uint32_t timestamp_clip;
//        std::vector<char> payload_clip;
//
//        // This is mutable because it's an intermediate buffer for
//        // the purpose of output.
//        //mutable vector<char> output_buffer;
//
//        enum Type
//        {
//            HORIZ,  // Horizontal, recursive
//            VERT,    // Vertical, recursive
//
//            // NOTE: HORIZ/VERT are defined as 0/1 so that not-inversion
//            // can flip between them.
//            SINGLE  // Horizontal-only with no recursion
//        };
//
//    };
//
//    struct RcvGroup: Group
//    {
//        bool fec;
//        bool dismissed;
//        RcvGroup(): fec(false), dismissed(false) {}
//
//#if ENABLE_HEAVY_LOGGING
//        std::string DisplayStats()
//        {
//            if (base == CSeqNo::m_iMaxSeqNo)
//                return "UNINITIALIZED!!!";
//
//            std::ostringstream os;
//            os << "base=" << base << " step=" << step << " drop=" << drop << " collected=" << collected
//                << " " << (fec ? "+" : "-") << "FEC " << (dismissed ? "DISMISSED" : "active");
//            return os.str();
//        }
//#endif
//    };

private:

//    struct Send
//    {
//        // We need only ONE horizontal group. Simply after the group
//        // is closed (last packet supplied), and the FEC packet extracted,
//        // the group is no longer in use.
//        Group row;
//        std::vector<Group> cols;
//    } snd;

//    struct Receive
//    {
//        SRTSOCKET id;
//        bool order_required;
//
//        Receive(std::vector<SrtPacket>& provided): id(SRT_INVALID_SOCK), order_required(false), rebuilt(provided)
//        {
//        }
//
//        // In reception we need to keep as many horizontal groups as required
//        // for possible later tracking. A horizontal group should be dismissed
//        // when the size of this container exceeds the `m_number_rows` (size of the column).
//        //
//        // The 'std::deque' type is used here for a trial implementation. A desired solution
//        // would be a kind of a ring buffer where new groups are added and old (exceeding
//        // the size) automatically dismissed.
//        std::deque<RcvGroup> rowq;
//
//        // Base index at the oldest column platform determines
//        // the base index of the queue. Meaning, first you need
//        // to determnine the column index, where the index 0 is
//        // the fistmost element of this queue. After determining
//        // the column index, there must be also a second factor
//        // deteremined - which column series it is. So, this can
//        // start by extracting the base sequence of the element
//        // at the index column. This is the series 0. Now, the
//        // distance between these two sequences, divided by
//        // rowsize*colsize should return %index-in-column,
//        // /number-series. The latter multiplied by the row size
//        // is the offset between the firstmost column and the
//        // searched column.
//        std::deque<RcvGroup> colq;
//
//        // This keeps the value of "packet received or not".
//        // The sequence number of the first cell is rowq[0].base.
//        // When dropping a row,
//        // - the firstmost element of rowq is removed
//        // - the length of one row is removed from this std::vector
//        int32_t cell_base;
//        std::deque<bool> cells;
//
//        // Note this function will automatically extend the container
//        // with empty cells if the index exceeds the size, HOWEVER
//        // the caller must make sure that this index isn't any "crazy",
//        // that is, it fits somehow in reasonable ranges.
//        bool CellAt(size_t index)
//        {
//            if (index >= cells.size())
//            {
//                // Cells not prepared for this sequence yet,
//                // so extend in advance.
//                cells.resize(index+1, false);
//                return false; // It wasn't marked, anyway.
//            }
//
//            return cells[index];
//        }
//
//        typedef SrtPacket PrivPacket;
//        std::vector<PrivPacket>& rebuilt;
//    } rcv;

//    void ConfigureGroup(Group& g, int32_t seqno, size_t gstep, size_t drop);
//    template <class Container>
//    void ConfigureColumns(Container& which, int32_t isn);
//
//    void ResetGroup(Group& g);
//
//    // Universal
//    void ClipData(Group& g, uint16_t length_net, uint8_t kflg,
//            uint32_t timestamp_hw, const char* payload, size_t payload_size);
//    void ClipPacket(Group& g, const CPacket& pkt);
//
//    // Sending
//    bool CheckGroupClose(Group& g, size_t pos, size_t size);
//    void PackControl(const Group& g, signed char groupix, SrtPacket& pkt, int32_t seqno);
//
//    // Receiving
////    void CheckLargeDrop(int32_t seqno);
////    int ExtendRows(int rowx);
////    int ExtendColumns(int colgx);
////    void MarkCellReceived(int32_t seq);
////    bool HangHorizontal(const CPacket& pkt, bool fec_ctl, loss_seqs_t& irrecover);
////    bool HangVertical(const CPacket& pkt, signed char fec_colx, loss_seqs_t& irrecover);
////    void ClipControlPacket(Group& g, const CPacket& pkt);
////    void ClipRebuiltPacket(Group& g, Receive::PrivPacket& pkt);
////    void RcvRebuild(Group& g, int32_t seqno, Group::Type tp);
////    int32_t RcvGetLossSeqHoriz(Group& g);
////    int32_t RcvGetLossSeqVert(Group& g);
//
//    static void TranslateLossRecords(const std::set<int32_t>& loss, loss_seqs_t& irrecover);
//    void RcvCheckDismissColumn(int32_t seqno, int colgx, loss_seqs_t& irrecover);
//    int RcvGetRowGroupIndex(int32_t seq);
//    int RcvGetColumnGroupIndex(int32_t seq);
//    void CollectIrrecoverRow(RcvGroup& g, loss_seqs_t& irrecover) const;
//    bool IsLost(int32_t seq) const;

};
#endif

#endif
