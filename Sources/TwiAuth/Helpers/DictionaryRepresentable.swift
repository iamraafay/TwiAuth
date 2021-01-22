//
//  DictionaryRepresentable.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-23.
//

import Foundation

protocol DictionaryRepresentable: Encodable {
    var dictionary: [String: Any] { get }
}

extension DictionaryRepresentable {
    var dictionary: [String: Any] {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        return (try? JSONSerialization.jsonObject(with: encoder.encode(self))) as? [String: Any] ?? [:]
    }
}
