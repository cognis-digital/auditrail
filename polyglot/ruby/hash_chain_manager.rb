# frozen_string_literal: true

require 'securerandom'
require 'time'
require 'json'

module AuditTrail
  # ============ Record ============
  class Record
    include Comparable
    
    attr_reader :id, :timestamp, :data, :parent_hash
    
    def initialize(id:, timestamp: Time.now.utc, data: nil, parent_hash: nil)
      @id = id || SecureRandom.uuid
      @timestamp = timestamp
      @data = data.is_a?(Hash) ? data.dup : (data.nil? ? {} : { raw: data })
      @parent_hash = parent_hash
    end
    
    def compute_hash
      # Include all mutable fields in hash calculation
      content = [id.to_s, @timestamp.iso8601, @data.inspect, parent_hash].join('::')
      Digest::SHA256.hexdigest(content)
    end
    
    def verify_parent!
      return true if parent_hash.nil?
      
      expected = compute_hash
      if expected != parent_hash
        raise IntegrityError, 
              "Parent hash mismatch: expected #{parent_hash}, got #{expected}"
      end
      
      true
    end
    
    def ==(other)
      other.is_a?(Record) && id == other.id && data == other.data
    end
    
    def inspect
      "#<AuditTrail::Record id=#{id[0..8]}... parent_hash=#{parent_hash[0..12]}...>"
    end
    
    def to_json(*args)
      {
        id: @id,
        timestamp: @timestamp.iso8601,
        data: @data,
        parent_hash: @parent_hash
      }.to_json(*args)
    end
    
    def self.from_json(json_str)
      hash = JSON.parse(json_str)
      new(
        id: hash[:id],
        timestamp: Time.iso8601(hash[:timestamp]),
        data: hash[:data],
        parent_hash: hash[:parent_hash]
      )
    end
    
    def <=>(other)
      @id <=> other.id if other.is_a?(Record)
    end
  end

  # ============ Integrity Error ============
  class IntegrityError < StandardError; end
  
  # ============ Chain Manager ============
  class ChainManager
    include Comparable
    
    attr_reader :head, :root_hash, :record_count
    
    def initialize(root_hash: nil)
      @records = []
      @root_hash = root_hash || SecureRandom.uuid[0..12]
      
      # Initialize with a genesis record if no root hash provided
      unless root_hash.nil? || root_hash.empty?
        create_genesis!
      end
    end
    
    def create_genesis!(data: {})
      @records << Record.new(
        id: 'genesis',
        timestamp: Time.now.utc,
        data: data,
        parent_hash: nil
      )
      
      # Genesis record's hash becomes the root hash for verification
      @root_hash = @records.first.compute_hash
      
      true
    end
    
    def add(data:, timestamp: Time.now.utc)
      prev_record = head || @records.last
      new_record = Record.new(
        id: SecureRandom.uuid,
        timestamp: timestamp,
        data: data.is_a?(Hash) ? data.dup : { raw: data },
        parent_hash: prev_record&.compute_hash
      )
      
      # Verify the chain before appending
      verify_chain!
      
      @records << new_record
      @head = new_record
      
      true
    end
    
    def append!(data)
      add(data: data, timestamp: Time.now.utc)
    end
    
    def head
      @head || (@records.last || nil)
    end
    
    def root_hash=(new_root)
      if new_root.is_a?(String) && !new_root.empty?
        # Update the genesis record's hash
        @root_hash = new_root
        create_genesis! unless @records.first.id == 'genesis'
      else
        raise ArgumentError, "Root hash must be a non-empty string"
      end
    end
    
    def verify_chain!
      return true if @records.empty?
      
      # Verify genesis record has no parent
      unless @records.first.parent_hash.nil?
        raise IntegrityError, 
              "Genesis record should have nil parent_hash but found: #{@records.first.parent_hash}"
      end
      
      # Verify each subsequent record's parent hash
      current_parent = nil
      @records.each do |record|
        expected_parent = current_parent&.compute_hash
        
        if !expected_parent.nil? && record.parent_hash != expected_parent
          raise IntegrityError, 
                "Record #{record.id} has wrong parent hash: expected #{expected_parent}, got #{record.parent_hash}"
        end
        
        # Verify this record's own computed hash matches its parent reference
        next unless current_parent.nil? || current_parent == @records.first
        
        if !record.verify_parent!
          raise IntegrityError, 
                "Record #{record.id} failed internal verification"
        end
        
        current_parent = record
      end
      
      # Verify final root hash matches stored root hash
      computed_root = head&.compute_hash || @root_hash
      unless computed_root == @root_hash
        raise IntegrityError, 
              "Root hash mismatch: stored #{@root_hash}, computed #{computed_root}"
      end
      
      true
    end
    
    def verify_record(record_id)
      record = find_by_id!(record_id)
      
      # Walk back to root and verify each link
      current = record
      while !current.parent_hash.nil?
        parent = find_by_parent_hash(current.parent_hash)
        
        if parent.nil? || parent.id != 'genesis' && parent.id != current.id
          return {
            record_id: record_id,
            verified: false,
            error: "Parent not found or broken chain at #{current.id}"
          }
        end
        
        unless current.verify_parent!
          return {
            record_id: record_id,
            verified: false,
            error: "Verification failed at #{current.id}: #{current.parent_hash[0..12]}..."
          }
        end
        
        current = parent
      end
      
      # Final check against root hash
      unless current.compute_hash == @root_hash
        return {
          record_id: record_id,
          verified: false,
          error: "Root hash mismatch for #{record.id}"
        }
      end
      
      true
    end
    
    def find_by_id!(id)
      @records.find do |r|
        r.id == id || (r.is_a?(Record) && r.data[:raw] == id)
      end || raise(ArgumentError, "No record found with id: #{id}")
    end
    
    def find_by_parent_hash(hash)
      @records.find { |r| r.parent_hash == hash }
    end
    
    def tamper!(record_id, new_data)
      # Find and modify a record to demonstrate tamper evidence
      record = find_by_id!(record_id)
      
      old_data = record.data.dup
      
      if record.id == 'genesis' || !head&.parent_hash.nil? && head != record
        raise IntegrityError, 
              "Tampering with #{record.id} will break the chain"
      end
      
      # Modify data (simulating a tamper)
      record.data = new_data.is_a?(Hash) ? new_data.dup : { raw: new_data }
      
      {
        record_id: record_id,
        old_data: old_data,
        new_data: record.data,
        parent_hash_unchanged: (record.parent_hash == head&.parent_hash)
      }
    end
    
    def detect_tamper!(record_id = nil)
      if record_id
        # Check specific record against its expected state
        record = find_by_id!(record_id)
        
        # Walk up the chain and verify each link
        current = record
        while !current.parent_hash.nil?
          parent = find_by_parent_hash(current.parent_hash)
          
          if parent.nil? || (parent.id != 'genesis' && parent.id != current.id)
            return {
              record_id: record_id,
              tampered: true,
              error: "Broken chain detected at #{current.id}"
            }
          end
          
          unless current.verify_parent!
            return {
              record_id: record_id,
              tampered: true,
              error: "Hash mismatch at #{current.id}"
            }
          end
          
          current = parent
        end
        
        # Check root hash
        unless current.compute_hash == @root_hash
          return {
            record_id: record_id,
            tampered: true,
            error: "Root hash mismatch"
          }
        end
      else
        # Full chain verification
        verify_chain!
        
        {
          record_id: nil,
          tampered: false,
          message: "Chain verified successfully"
        }
      end
    end
    
    def load_from_file(path)
      File.read(path).each_line do |line|
        if line.strip.empty? || line.start_with?('#')
          next
        end
        
        record = Record.from_json(line.strip)
        
        # Verify parent hash before adding
        unless record.parent_hash.nil? || head&.compute_hash == record.parent_hash
          raise IntegrityError, 
                "Loaded record has unexpected parent hash"
        end
        
        @records << record
      end
      
      verify_chain!
      
      true
    end
    
    def save_to_file(path)
      File.open(path, 'w') do |f|
        f.write("# Audit Trail Chain\n")
        f.write("# Root Hash: #{@root_hash}\n")
        f.write("# Records: #{record_count}\n")
        
        @records.each do |r|
          f.write(r.to_json + "\n")
        end
      end
      
      true
    end
    
    def clear!
      # Remove all records except genesis if it exists
      if @records.first.id == 'genesis'
        @records = [@records.first]
        @head = @records.first
      else
        @records.clear
        create_genesis!
      end
      
      true
    end
    
    def reset!(root_hash: nil)
      clear!
      self.root_hash = root_hash || SecureRandom.uuid[0..12]
      
      true
    end
    
    def to_json(*args)
      {
        root_hash: @root_hash,
        record_count: @records.size,
        head_id: head&.id,
        records: @records.map(&:to_json)
      }.to_json(*args)
    end
    
    def inspect
      "#<AuditTrail::ChainManager " \
      "head=#{head&.id || 'nil'}, " \
      "root_hash=#{@root_hash[0..12]}..., " \
      "records=#{record_count}>"
    end
    
    def <=>(other)
      @root_hash <=> other.root_hash if other.is_a?(ChainManager)
    end
  end

  # ============ Convenience Factory ============
  module Factory
    def self.create_chain(root_hash: nil, data: {})
      manager = ChainManager.new(root_hash: root_hash)
      
      if !root_hash.nil? && !root_hash.empty?
        manager.root_hash = root_hash
      end
      
      # Add genesis record with optional initial data
      manager.create_genesis!(data: data)
      
      manager
    end
    
    def self.from_file(path, root_hash: nil)
      manager = ChainManager.new(root_hash: root_hash)
      manager.load_from_file(path)
      manager
    rescue Errno::ENOENT
      raise "File not found: #{path}"
    rescue IntegrityError => e
      raise "Loaded chain has integrity issues: #{e.message}"
    end
    
    def self.to_json(manager, path = nil)
      if path
        File.write(path, manager.to_json)
        path
      else
        manager.to_json
      end
    end
  end

  # ============ Public API ============
  class << self
    def create_chain(root_hash: nil, data: {})
      Factory.create_chain(root_hash: root_hash, data: data)
    end
    
    def from_file(path, root_hash: nil)
      Factory.from_file(path, root_hash: root_hash)
    end
    
    def to_json(manager, path = nil)
      Factory.to_json(manager, path)
    end
    
    def create_genesis(root_hash: nil, data: {})
      manager = ChainManager.new(root_hash: root_hash)
      manager.create_genesis!(data: data)
      manager
    end
  end

  # ============ Demo / Entry Point ============
  if __FILE__ == $0
    puts "=" * 60
    puts "AuditTrail::HashChainManager - Interactive Demo"
    puts "=" * 60
    
    def self.print_header(title)
      puts "\n#{title}"
      puts "-" * (title.length + 4)
    end
    
    def self.print_record(record, label = "")
      puts "#{label}Record: #{record.id[0..8]}..."
      puts "  Timestamp: #{record.timestamp.iso8601}"
      puts "  Data: #{record.data.inspect.truncate(50)}#{'...' if record.data.to_s.length > 50}"
      puts "  Parent Hash: #{record.parent_hash[0..12]}..." if record.parent_hash
    end
    
    # Create a new chain
    print_header("Step 1: Creating New Chain")
    
    manager = AuditTrail::Factory.create_chain(
      root_hash: 'demo-root-123456789',
      data: { app_name: 'auditrail-demo' }
    )
    
    puts "Created chain with root hash: #{manager.root_hash}"
    print_record(manager.head, "  ")
    
    # Add some records
    print_header("Step 2: Adding Records")
    
    [1, 2, 3].each do |i|
      manager.add(
        data: { action: :write, user: "user#{i}", resource: "/data/#{i}" },
        timestamp: Time.now.utc + i * 60
      )
      
      print_record(manager.head, "    ")
    end
    
    # Verify the chain
    print_header("Step 3: Verifying Chain Integrity")
    
    begin
      result = manager.verify_chain!
      puts "  Result: #{result ? 'PASS' : 'FAIL'}"
    rescue AuditTrail::IntegrityError => e
      puts "  Result: FAIL - #{e.message}"
    end
    
    # Verify a specific record
    print_header("Step 4: Verifying Specific Record")
    
    begin
      result = manager.verify_record('01234567-89ab-cdef-0123-456789abcdef')
      puts "  Result: #{result.inspect}"
    rescue AuditTrail::IntegrityError => e
      puts "  Result: FAIL - #{e.message}"
    end
    
    # Demonstrate tamper detection
    print_header("Step 5: Detecting Tampering")
    
    begin
      result = manager.detect_tamper!
      puts "  Result: #{result.inspect}"
    rescue AuditTrail::IntegrityError => e
      puts "  Result: FAIL - #{e.message}"
    end
    
    # Demonstrate manual tampering
    print_header("Step 6: Manual Tampering")
    
    begin
      old_data = manager.head.data.dup
      
      result = manager.tamper!(manager.head.id, { action: :modified, user: 'attacker' })
      
      puts "  Modified record #{result[:record_id]}"
      puts "  Old data: #{old_data.inspect}"
      puts "  New data: #{result[:new_data].inspect}"
    rescue AuditTrail::IntegrityError => e
      puts "  Error during tamper: #{e.message}"
    end
    
    # Verify after tampering
    print_header("Step 7: Verification After Tampering")
    
    begin
      result = manager.verify_chain!
      puts "  Result: #{result ? 'PASS' : 'FAIL'}"
    rescue AuditTrail::IntegrityError => e
      puts "  Result: FAIL - #{e.message}"
    end
    
    # Save and reload
    print_header("Step 8: Persistence Test")
    
    temp_file = '/tmp/auditrail_demo.json'
    
    begin
      manager.save_to_file(temp_file)
      puts "  Saved to: #{temp_file}"
      
      new_manager = AuditTrail::Factory.from_file(temp_file)
      puts "  Loaded chain root hash: #{new_manager.root_hash[0..12]}..."
      
      # Verify loaded chain matches original
      if manager.root_hash == new_manager.root_hash && 
         manager.record_count == new_manager.record_count
        puts "  Persistence check: PASS"
      else
        puts "  Persistence check: FAIL (mismatch)"
      end
      
    ensure
      File.delete(temp_file)