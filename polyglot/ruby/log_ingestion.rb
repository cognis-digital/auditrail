require 'securerandom'
require 'json'
require 'time'
require 'digest/sha256'

module AuditTrail
  VERSION = "1.0.0"

  class LogEntry < Struct.new(:id, :timestamp, :source, :data, :prev_hash, :entry_hash)
    include Comparable
    
    def initialize(id:, timestamp: Time.now.utc, source:, data:, prev_hash: nil)
      @id = id
      @timestamp = timestamp
      @source = source
      @data = data.is_a?(Hash) ? JSON.generate(data) : data.to_s
      @prev_hash = prev_hash
      
      # Compute this entry's hash (includes all fields + previous hash)
      raw = "#{@id}|#{@timestamp.iso8601}|#{@source}|#{@data}|#{@prev_hash}"
      @entry_hash = Digest::SHA256.hexdigest(raw)
    end

    def to_json(options = {})
      JSON.generate({ id: @id, timestamp: @timestamp.iso8601, source: @source, 
                     data: @data, prev_hash: @prev_hash, entry_hash: @entry_hash }, options)
    end

    def self.from_json(json_str)
      obj = JSON.parse(json_str)
      new(id: obj[:id], timestamp: Time.iso8601(obj[:timestamp]), 
          source: obj[:source], data: obj[:data], prev_hash: obj[:prev_hash])
    end

    def ==(other)
      other.is_a?(LogEntry) && @id == other.id && @entry_hash == other.entry_hash
    end
  end

  class ChainError < StandardError; end

  class Aggregator
    attr_reader :chain, :metadata
    
    def initialize(options = {})
      @options = options
      @metadata = { version: AuditTrail::VERSION, created_at: Time.now.utc.iso8601 }
      @chain = []
    end

    # Add a new log entry to the chain
    def add(source:, data:)
      prev_hash = @chain.empty? ? nil : @chain.last.entry_hash
      
      id = SecureRandom.uuid
      timestamp = Time.now.utc
      entry = LogEntry.new(id: id, source: source, data: data, prev_hash: prev_hash)
      
      @chain << entry
      self
    end

    # Verify the entire chain integrity from root to current tip
    def verify!
      return true if @chain.empty?
      
      expected = nil
      @chain.each do |entry|
        raw = "#{entry.id}|#{entry.timestamp.iso8601}|#{entry.source}|#{entry.data}|#{expected}"
        computed = Digest::SHA256.hexdigest(raw)
        
        if computed != entry.entry_hash
          raise ChainError, "Chain break at entry #{entry.id}: expected #{computed}, got #{entry.entry_hash}"
        end
        
        expected = entry.entry_hash
      end
      
      true
    rescue ChainError => e
      puts "[VERIFY] #{e.message}"
      false
    end

    # Export the entire chain as JSON (portable snapshot)
    def export(options = {})
      { metadata: @metadata, entries: @chain.map(&:to_json), 
        tip_hash: @chain.empty? ? nil : @chain.last.entry_hash }.to_json(options)
    end

    # Import a previously exported chain
    def import(json_str)
      obj = JSON.parse(json_str)
      
      @metadata = obj[:metadata] || {}
      @chain = obj[:entries].map { |e| LogEntry.from_json(e.to_s) }
      self
    end

    # Get a summary of the chain state
    def summary
      total = @chain.size
      root_hash = @chain.first&.prev_hash
      tip_hash = @chain.last&.entry_hash
      
      { total: total, root_hash: root_hash, 
        tip_hash: tip_hash, created_at: @metadata[:created_at] }
    end

    # Reset the chain (clears all entries)
    def reset!
      @chain.clear
      self
    end
  end
end

# =============================================================================
# DEMO / RUNNABLE ENTRY POINT
# =============================================================================

if __FILE__ == $0
  puts "=" * 60
  puts "AuditTrail Log Ingestion Demo"
  puts "=" * 60
  
  # Create a new aggregator instance
  aggregator = AuditTrail::Aggregator.new(
    app_name: "demo-app", 
    environment: "development"
  )

  puts "\n1. Adding log entries to the chain..."
  
  # Simulate receiving logs from different sources
  sample_logs = [
    { source: "web_server", data: { event: "user_login", user_id: 42, ip: "192.168.1.5" } },
    { source: "database", data: { event: "query_executed", sql_hash: "abc123", duration_ms: 15 } },
    { source: "web_server", data: { event: "page_view", page: "/dashboard", referrer: nil } },
    { source: "auth_service", data: { event: "token_refreshed", token_type: "access" } }
  ]

  sample_logs.each do |log|
    aggregator.add(source: log[:source], data: log[:data])
    puts "   Added entry #{aggregator.chain.last.id} from #{log[:source]}"
  end

  puts "\n2. Verifying chain integrity..."
  valid = aggregator.verify!
  puts "   Chain status: #{valid ? 'VALID' : 'BROKEN'}"

  puts "\n3. Getting summary..."
  summary = aggregator.summary
  puts "   Total entries: #{summary[:total]}"
  puts "   Root hash: #{summary[:root_hash] || 'nil (first entry)'}"
  puts "   Tip hash: #{summary[:tip_hash]}"

  puts "\n4. Exporting chain for portability..."
  exported = aggregator.export(indent: 2)
  puts "   Exported size: #{exported.bytesize} bytes"
  
  # Simulate storing the export (e.g., to S3, database, or file system)
  # In production, you'd write this to persistent storage

  puts "\n5. Testing import and re-verification..."
  imported = AuditTrail::Aggregator.new
  imported.import(exported)
  
  if imported.verify!
    puts "   Imported chain verified successfully"
  else
    puts "   Imported chain has issues!"
  end

  puts "\n6. Simulating tamper detection..."
  # Manually corrupt one entry's hash to simulate tampering
  corrupted = exported.dup
  obj = JSON.parse(corrupted)
  
  if obj[:entries].any? { |e| e.is_a?(String) }
    entries_json = obj[:entries]
  else
    entries_json = obj[:entries].map(&:to_s)
  end
  
  # Corrupt the middle entry's hash
  corrupted_entries = entries_json.map do |entry_json|
    if entry_json.include?('"event": "user_login"')
      obj_corrupted = JSON.parse(entry_json)
      obj_corrupted[:entry_hash] = "CORRUPTED_HASH_999"
      JSON.generate(obj_corrupted)
    else
      entry_json
    end
  end
  
  corrupted_obj = { metadata: obj[:metadata], entries: corrupted_entries, 
                    tip_hash: obj[:tip_hash] }
  
  imported2 = AuditTrail::Aggregator.new
  imported2.import(JSON.generate(corrupted_obj))
  
  puts "   After corruption, verification result:"
  begin
    imported2.verify!
    puts "     Unexpectedly passed (may indicate subtle bug)"
  rescue AuditTrail::ChainError => e
    puts "     Correctly detected tampering: #{e.message}"
  end

  puts "\n7. Final state before reset..."
  puts aggregator.summary.inspect
  
  # Clean up for next run
  aggregator.reset!
  
  puts "\n8. After reset (empty chain)..."
  puts aggregator.summary.inspect
  puts aggregator.verify! ? "   Empty chain is valid" : ""

  puts "\n" + "=" * 60
  puts "Demo complete. Check output for tamper detection results."
  puts "=" * 60
end