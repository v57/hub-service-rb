# frozen_string_literal: true

module HubServiceRB
  # An app: a header plus a UI body of elements (TS app.ts parity).
  # body is an Array — plain strings (shorthand text) or element hashes built
  # with the helpers below.
  class App
    attr_accessor :header, :body, :top, :bottom, :data

    def initialize(header:, body: [], top: nil, bottom: nil, data: {})
      @header = header
      @body = body
      @top = top
      @bottom = bottom
      @data = data
    end
  end

  # Element helpers produce element hashes matching the TS app.ts wire shapes.

  # Action references an API call from a UI element.
  def self.action(path, body = nil, output = nil)
    a = { path: path }
    a[:body] = body unless body.nil?
    a[:output] = output unless output.nil?
    a
  end

  def self.text(value)
    { type: 'text', value: value }
  end

  def self.progress(value, min = nil, max = nil)
    e = { type: 'progress', value: value }
    e[:min] = min unless min.nil?
    e[:max] = max unless max.nil?
    e
  end

  def self.text_field(value, placeholder = nil, action = nil)
    e = { type: 'textField', value: value }
    e[:placeholder] = placeholder unless placeholder.nil?
    e[:action] = action unless action.nil?
    e
  end

  def self.button(title, action)
    { type: 'button', title: title, action: action }
  end

  def self.slider(value, default_value = nil, min = nil, max = nil, step = nil, action = nil)
    e = { type: 'slider', value: value }
    e[:defaultValue] = default_value unless default_value.nil?
    e[:min] = min unless min.nil?
    e[:max] = max unless max.nil?
    e[:step] = step unless step.nil?
    e[:action] = action unless action.nil?
    e
  end

  def self.list(data, content)
    { type: 'list', data: data, content: content }
  end

  def self.picker(options, selected)
    { type: 'picker', options: options, selected: selected }
  end

  def self.cell(title = nil, subtitle = nil)
    e = { type: 'cell' }
    e[:title] = title unless title.nil?
    e[:subtitle] = subtitle unless subtitle.nil?
    e
  end

  def self.files(value, title = nil, action = nil)
    e = { type: 'files', value: value }
    e[:title] = title unless title.nil?
    e[:action] = action unless action.nil?
    e
  end

  def self.file_operation(format = nil, title = nil, action = nil)
    e = { type: 'fileOperation' }
    e[:format] = format unless format.nil?
    e[:title] = title unless title.nil?
    e[:action] = action unless action.nil?
    e
  end

  def self.hstack(content, spacing = nil)
    e = { type: 'hstack', content: content }
    e[:spacing] = spacing unless spacing.nil?
    e
  end

  def self.vstack(content, spacing = nil)
    e = { type: 'vstack', content: content }
    e[:spacing] = spacing unless spacing.nil?
    e
  end

  def self.zstack(content)
    { type: 'zstack', content: content }
  end

  def self.spacer
    { type: 'spacer' }
  end
end
